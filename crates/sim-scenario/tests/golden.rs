//! R11 deterministic golden-fixture scenarios: LAN-local ARP resolution and
//! forward, WAN routing with UDP/TCP NAT, and firewall allow/deny, driven
//! through the public full composition API.

mod support;

use ruster_core::{IfId, MonotonicMillis};
use ruster_sim_scenario::{
    run_scenario, FrameOrigin, PublicationSummary, Scenario, ScenarioIngress, ScenarioTick, TxFrame,
};
use support::{
    arp_reply, arp_request, independent_checksum, independent_transport_checksum, tcp_syn_frame,
    tcp_syn_frame_with_window, udp_frame, EthernetHop, DIRECT_WAN_ROUTE, FULL_SERVICE, HOST_IP,
    HOST_MAC, LAN, LAN_HOP, LAN_IP, LAN_MAC, REMOTE_IP, RESOLVABLE_HOST_IP, RESOLVABLE_HOST_MAC,
    UDP_NAT, UNREACHABLE_HOST_IP, WAN, WAN_IP, WAN_MAC, WAN_NEXT_HOP_MAC,
};

fn one_tick_scenario(
    name: &'static str,
    config_toml: &'static str,
    seed: u64,
    interface: IfId,
    frame: Vec<u8>,
) -> Scenario {
    Scenario {
        name,
        config_toml,
        generation: 7,
        seed,
        ticks: vec![ScenarioTick {
            now: MonotonicMillis(0),
            ingress: vec![ScenarioIngress::new(interface, frame)],
        }],
    }
}

fn assert_udp_nat_wire(forwarded: &TxFrame) {
    assert_eq!(forwarded.sequence, 0);
    assert_eq!(forwarded.ingress, LAN);
    assert_eq!(forwarded.egress, WAN);
    assert_eq!(forwarded.origin, FrameOrigin::Received { ingress: LAN });
    let expected = udp_frame(
        EthernetHop {
            dest_mac: WAN_NEXT_HOP_MAC,
            src_mac: WAN_MAC,
        },
        WAN_IP,
        REMOTE_IP,
        40_005,
        53,
        63,
        b"query",
    );
    assert_eq!(forwarded.bytes, expected, "full UDP wire bytes");
    assert_eq!(forwarded.bytes.len(), 47);
    assert_eq!(&forwarded.bytes[0..6], &WAN_NEXT_HOP_MAC);
    assert_eq!(&forwarded.bytes[6..12], &WAN_MAC);
    assert_eq!(&forwarded.bytes[12..14], &0x0800_u16.to_be_bytes());
    let ip = &forwarded.bytes[14..34];
    assert_eq!(ip[0], 0x45, "IPv4 version and IHL");
    assert_eq!(ip[1], 0, "DSCP/ECN");
    assert_eq!(&ip[2..4], &33_u16.to_be_bytes(), "IPv4 total length");
    assert_eq!(&ip[4..6], &0_u16.to_be_bytes(), "IPv4 identification");
    assert_eq!(&ip[6..8], &0x4000_u16.to_be_bytes(), "IPv4 flags/offset");
    assert_eq!(ip[8], 63, "TTL decremented by one hop");
    assert_eq!(ip[9], 17, "still UDP");
    assert_eq!(independent_checksum(ip), 0, "IPv4 checksum");
    assert_eq!(
        &ip[12..16],
        &WAN_IP,
        "source rewritten to the NAT public address"
    );
    assert_eq!(&ip[16..20], &REMOTE_IP, "destination is untouched");
    let udp = &forwarded.bytes[34..];
    assert_eq!(udp.len(), 13);
    assert_eq!(
        &udp[0..2],
        &40005_u16.to_be_bytes(),
        "fixed translated UDP source port"
    );
    assert_eq!(
        &udp[2..4],
        &53_u16.to_be_bytes(),
        "destination port is untouched"
    );
    assert_eq!(&udp[4..6], &13_u16.to_be_bytes(), "UDP length");
    let mut udp_without_checksum = udp.to_vec();
    udp_without_checksum[6..8].fill(0);
    let mathematical_checksum = independent_transport_checksum(ip, 17, &udp_without_checksum);
    let expected_wire_checksum = if mathematical_checksum == 0 {
        0xffff
    } else {
        mathematical_checksum
    };
    assert_eq!(
        u16::from_be_bytes([udp[6], udp[7]]),
        expected_wire_checksum,
        "UDP checksum field uses present-checksum zero normalization"
    );
    assert_eq!(
        independent_transport_checksum(ip, 17, udp),
        0,
        "UDP checksum residue"
    );
    assert_eq!(&udp[8..], b"query");
}

fn assert_tcp_nat_wire(forwarded: &TxFrame) {
    assert_eq!(forwarded.sequence, 0);
    assert_eq!(forwarded.ingress, LAN);
    assert_eq!(forwarded.egress, WAN);
    assert_eq!(forwarded.origin, FrameOrigin::Received { ingress: LAN });
    let expected = tcp_syn_frame(
        EthernetHop {
            dest_mac: WAN_NEXT_HOP_MAC,
            src_mac: WAN_MAC,
        },
        WAN_IP,
        REMOTE_IP,
        40_011,
        443,
        63,
        1_000,
    );
    assert_eq!(forwarded.bytes, expected, "full TCP wire bytes");
    assert_eq!(forwarded.bytes.len(), 54);
    assert_eq!(&forwarded.bytes[0..6], &WAN_NEXT_HOP_MAC);
    assert_eq!(&forwarded.bytes[6..12], &WAN_MAC);
    assert_eq!(&forwarded.bytes[12..14], &0x0800_u16.to_be_bytes());
    let ip = &forwarded.bytes[14..34];
    assert_eq!(ip[0], 0x45, "IPv4 version and IHL");
    assert_eq!(ip[1], 0, "DSCP/ECN");
    assert_eq!(&ip[2..4], &40_u16.to_be_bytes(), "IPv4 total length");
    assert_eq!(&ip[4..6], &0_u16.to_be_bytes(), "IPv4 identification");
    assert_eq!(&ip[6..8], &0x4000_u16.to_be_bytes(), "IPv4 flags/offset");
    assert_eq!(ip[8], 63, "TTL decremented by one hop");
    assert_eq!(ip[9], 6, "still TCP");
    assert_eq!(independent_checksum(ip), 0, "IPv4 checksum");
    assert_eq!(&ip[12..16], &WAN_IP);
    assert_eq!(&ip[16..20], &REMOTE_IP);
    let tcp = &forwarded.bytes[34..];
    assert_eq!(tcp.len(), 20);
    assert_eq!(
        &tcp[0..2],
        &40011_u16.to_be_bytes(),
        "fixed translated TCP source port"
    );
    assert_eq!(&tcp[2..4], &443_u16.to_be_bytes());
    assert_eq!(&tcp[4..8], &1_000_u32.to_be_bytes(), "sequence");
    assert_eq!(&tcp[8..12], &0_u32.to_be_bytes(), "acknowledgement");
    assert_eq!(tcp[12] >> 4, 5, "TCP data offset");
    assert_eq!(tcp[12] & 0x0f, 0, "TCP reserved bits");
    assert_eq!(tcp[13], 0x02, "SYN flags");
    assert_eq!(&tcp[14..16], &64_240_u16.to_be_bytes(), "window");
    let mut tcp_without_checksum = tcp.to_vec();
    tcp_without_checksum[16..18].fill(0);
    let mathematical_checksum = independent_transport_checksum(ip, 6, &tcp_without_checksum);
    assert_eq!(
        u16::from_be_bytes([tcp[16], tcp[17]]),
        mathematical_checksum,
        "TCP checksum field preserves mathematical zero"
    );
    assert_eq!(
        independent_transport_checksum(ip, 6, tcp),
        0,
        "TCP checksum residue"
    );
    assert_eq!(&tcp[18..20], &0_u16.to_be_bytes(), "urgent pointer");
}

#[test]
fn lan_local_arp_request_resolves_and_forwards_no_transit() {
    let scenario = one_tick_scenario(
        "lan_local_arp",
        FULL_SERVICE,
        11,
        LAN,
        arp_request(HOST_MAC, HOST_IP, LAN_IP),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    assert_eq!(outcomes.len(), 1);
    let tick = &outcomes[0];
    assert_eq!(
        tick.publication,
        PublicationSummary::Unchanged,
        "no successor candidate was supplied"
    );
    assert!(tick.active);
    assert_eq!(
        tick.tx.len(),
        1,
        "the router answers the ARP request itself"
    );
    let reply = &tick.tx[0];
    assert_eq!(reply.ingress, LAN);
    assert_eq!(reply.egress, LAN);
    assert_eq!(reply.origin, FrameOrigin::Received { ingress: LAN });
    assert_eq!(&reply.bytes[0..6], &HOST_MAC);
    assert_eq!(&reply.bytes[6..12], &LAN_MAC);
    assert_eq!(
        &reply.bytes[20..22],
        &2_u16.to_be_bytes(),
        "ARP reply opcode"
    );
    assert_eq!(&reply.bytes[22..28], &LAN_MAC);
    assert_eq!(&reply.bytes[28..32], &LAN_IP);
    assert_eq!(&reply.bytes[32..38], &HOST_MAC);
    assert_eq!(&reply.bytes[38..42], &HOST_IP);
}

#[test]
fn wan_route_udp_nat_translates_and_forwards_to_next_hop() {
    let scenario = one_tick_scenario(
        "wan_udp_nat",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    let tick = &outcomes[0];
    assert!(tick.active);
    assert_eq!(
        tick.tx.len(),
        1,
        "the UDP datagram is NAT'd and forwarded once"
    );
    assert_udp_nat_wire(&tick.tx[0]);
}

#[test]
fn r11sim_024_udp_full_wire_oracle_is_independent() {
    let scenario = one_tick_scenario(
        "udp-independent-wire-oracle",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].tx.len(), 1);
    assert_udp_nat_wire(&outcomes[0].tx[0]);
}

#[test]
fn r11sim_028_udp_present_checksum_negative_zero_is_wire_ffff() {
    let payload: &[u8] = &[0x00, 0x00, 0xfd, 0x15, 0x00];
    let scenario = one_tick_scenario(
        "udp-negative-zero",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, payload),
    );
    let outcomes = run_scenario(&scenario).expect("negative-zero UDP scenario must run");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].tx.len(), 1);
    let forwarded = &outcomes[0].tx[0];
    let expected = udp_frame(
        EthernetHop {
            dest_mac: WAN_NEXT_HOP_MAC,
            src_mac: WAN_MAC,
        },
        WAN_IP,
        REMOTE_IP,
        40_005,
        53,
        63,
        payload,
    );
    assert_eq!(forwarded.bytes, expected, "full negative-zero UDP wire");
    let ip = &forwarded.bytes[14..34];
    let udp = &forwarded.bytes[34..];
    let mut zeroed = udp.to_vec();
    zeroed[6..8].fill(0);
    assert_eq!(independent_transport_checksum(ip, 17, &zeroed), 0);
    assert_eq!(&udp[6..8], &[0xff, 0xff]);
}

#[test]
fn wan_route_tcp_syn_firewall_allow_nats_and_forwards() {
    let scenario = one_tick_scenario(
        "wan_tcp_allow",
        FULL_SERVICE,
        11,
        LAN,
        tcp_syn_frame(LAN_HOP, HOST_IP, REMOTE_IP, 52_000, 443, 64, 1000),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    let tick = &outcomes[0];
    assert!(tick.active);
    assert_eq!(
        tick.tx.len(),
        1,
        "the allowed TCP SYN is NAT'd and forwarded once"
    );
    assert_tcp_nat_wire(&tick.tx[0]);
}

#[test]
fn r11sim_025_tcp_full_wire_oracle_is_independent() {
    let scenario = one_tick_scenario(
        "tcp-independent-wire-oracle",
        FULL_SERVICE,
        11,
        LAN,
        tcp_syn_frame(LAN_HOP, HOST_IP, REMOTE_IP, 52_000, 443, 64, 1000),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].tx.len(), 1);
    assert_tcp_nat_wire(&outcomes[0].tx[0]);
}

#[test]
fn r11sim_029_tcp_mathematical_zero_stays_wire_zero() {
    let sequence = 45_191_u32;
    // The required sequence and translated tuple reach mathematical zero with
    // this test-owned SYN window. The ordinary golden SYN window is a nearby
    // non-zero case, so keep the boundary input explicit here.
    let scenario = one_tick_scenario(
        "tcp-zero-checksum",
        FULL_SERVICE,
        11,
        LAN,
        tcp_syn_frame_with_window(
            LAN_HOP, HOST_IP, REMOTE_IP, 52_000, 443, 64, sequence, 64_272,
        ),
    );
    let outcomes = run_scenario(&scenario).expect("zero-checksum TCP scenario must run");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].tx.len(), 1);
    let forwarded = &outcomes[0].tx[0];
    let expected = tcp_syn_frame_with_window(
        EthernetHop {
            dest_mac: WAN_NEXT_HOP_MAC,
            src_mac: WAN_MAC,
        },
        WAN_IP,
        REMOTE_IP,
        40_011,
        443,
        63,
        sequence,
        64_272,
    );
    assert_eq!(forwarded.bytes, expected, "full zero-checksum TCP wire");
    let ip = &forwarded.bytes[14..34];
    let tcp = &forwarded.bytes[34..];
    let mut zeroed = tcp.to_vec();
    zeroed[16..18].fill(0);
    assert_eq!(independent_transport_checksum(ip, 6, &zeroed), 0);
    assert_eq!(&tcp[16..18], &[0x00, 0x00]);
}

#[test]
fn wan_route_udp_firewall_deny_drops_without_transmission() {
    let scenario = one_tick_scenario(
        "wan_udp_deny",
        FULL_SERVICE,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    let tick = &outcomes[0];
    assert!(tick.active);
    assert!(
        tick.tx.is_empty(),
        "the default-deny UDP rule drops the datagram, nothing is transmitted"
    );
}

#[test]
fn dynamic_neighbor_resolution_then_forward_across_two_ticks() {
    // Tick 0: the LAN host sends a UDP datagram to a WAN host with no known
    // neighbor. The route is directly-connected, so the router schedules an
    // ARP request for the destination itself and drops this first datagram
    // (no queued replay); this mirrors the exact miss/schedule path the
    // `host_unreachable_after_max_arp_attempts_...` scenario also exercises,
    // just resolved instead of exhausted.
    let tick0 = ScenarioTick {
        now: MonotonicMillis(0),
        ingress: vec![ScenarioIngress::new(
            LAN,
            udp_frame(
                LAN_HOP,
                HOST_IP,
                RESOLVABLE_HOST_IP,
                51_100,
                53,
                64,
                b"hello",
            ),
        )],
    };
    // Tick 1: the WAN host answers with an ARP reply before the next retry
    // interval elapses. `merge_dynamic` learns it as a dynamic neighbor and
    // produces no transmission of its own.
    let tick1 = ScenarioTick {
        now: MonotonicMillis(500),
        ingress: vec![ScenarioIngress::new(
            WAN,
            arp_reply(RESOLVABLE_HOST_MAC, RESOLVABLE_HOST_IP, WAN_MAC, WAN_IP),
        )],
    };
    // Tick 2: the same datagram is sent again. The neighbor is now resolved,
    // so it is NAT'd and forwarded to the learned MAC instead of triggering
    // another ARP request.
    let tick2 = ScenarioTick {
        now: MonotonicMillis(600),
        ingress: vec![ScenarioIngress::new(
            LAN,
            udp_frame(
                LAN_HOP,
                HOST_IP,
                RESOLVABLE_HOST_IP,
                51_100,
                53,
                64,
                b"hello",
            ),
        )],
    };
    let scenario = Scenario {
        name: "dynamic_arp_then_forward",
        config_toml: DIRECT_WAN_ROUTE,
        generation: 7,
        seed: 11,
        ticks: vec![tick0, tick1, tick2],
    };
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    assert_eq!(outcomes.len(), 3);
    for outcome in &outcomes {
        assert!(outcome.active);
    }

    let request_tick = &outcomes[0];
    assert!(
        request_tick.tx.is_empty() || request_tick.tx.len() == 1,
        "tick 0 drops the unresolved datagram and may emit the ARP request"
    );
    assert_eq!(
        request_tick.tx.len(),
        1,
        "tick 0 emits exactly one generated ARP request, the datagram itself is dropped"
    );
    let request = &request_tick.tx[0];
    assert_eq!(request.egress, WAN);
    assert_eq!(&request.bytes[0..6], &[0xff; 6], "ARP request is broadcast");
    assert_eq!(&request.bytes[6..12], &WAN_MAC, "router originates it");
    assert_eq!(
        &request.bytes[38..42],
        &RESOLVABLE_HOST_IP,
        "target is the unresolved WAN host"
    );

    let reply_tick = &outcomes[1];
    assert!(
        reply_tick.tx.is_empty(),
        "an ARP reply is only consumed and learned, it generates no transmission"
    );

    let forward_tick = &outcomes[2];
    assert_eq!(
        forward_tick.tx.len(),
        1,
        "the second datagram uses the now-resolved neighbor and is forwarded"
    );
    let forwarded = &forward_tick.tx[0];
    assert_eq!(forwarded.ingress, LAN);
    assert_eq!(forwarded.egress, WAN);
    assert_eq!(
        &forwarded.bytes[0..6],
        &RESOLVABLE_HOST_MAC,
        "destination MAC is the neighbor learned from the tick 1 ARP reply"
    );
    assert_eq!(&forwarded.bytes[6..12], &WAN_MAC);
    let ip = &forwarded.bytes[14..34];
    assert_eq!(ip[9], 17, "still UDP");
    assert_eq!(
        &ip[12..16],
        &WAN_IP,
        "source rewritten to the NAT public address"
    );
    assert_eq!(
        &ip[16..20],
        &RESOLVABLE_HOST_IP,
        "destination is the resolved WAN host"
    );
    let udp = &forwarded.bytes[34..];
    assert_eq!(
        &udp[2..4],
        &53_u16.to_be_bytes(),
        "destination port is untouched"
    );
    assert_ne!(
        u16::from_be_bytes([udp[0], udp[1]]),
        51_100,
        "source port is remapped to an allocated public port"
    );
    assert_eq!(&udp[8..], b"hello");
}

#[test]
fn wan_route_ttl_exceeded_generates_icmpv4_time_exceeded_reply() {
    let scenario = one_tick_scenario(
        "ttl_exceeded",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 1, b"query"),
    );
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    let tick = &outcomes[0];
    assert!(tick.active);
    assert_eq!(
        tick.tx.len(),
        1,
        "the router generates one ICMPv4 time-exceeded reply, it does not forward the datagram"
    );
    let reply = &tick.tx[0];
    assert_eq!(reply.ingress, LAN);
    assert_eq!(
        reply.egress, LAN,
        "the reply returns out the ingress interface"
    );
    assert_eq!(reply.origin, FrameOrigin::Generated);
    assert_eq!(&reply.bytes[0..6], &HOST_MAC, "back to the original sender");
    assert_eq!(&reply.bytes[6..12], &LAN_MAC);
    let ip = &reply.bytes[14..34];
    assert_eq!(ip[9], 1, "ICMP protocol");
    assert_eq!(
        &ip[12..16],
        &LAN_IP,
        "the router originates the error itself"
    );
    assert_eq!(
        &ip[16..20],
        &HOST_IP,
        "addressed back to the original sender"
    );
    let icmp = &reply.bytes[34..];
    assert_eq!(icmp[0], 11, "ICMPv4 type 11: time exceeded");
    assert_eq!(icmp[1], 0, "code 0: TTL exceeded in transit");
    let quoted_ip = &icmp[8..28];
    assert_eq!(quoted_ip[8], 1, "quotes the original datagram's TTL of 1");
    assert_eq!(quoted_ip[9], 17, "quotes the original UDP protocol");
    assert_eq!(
        &quoted_ip[12..16],
        &HOST_IP,
        "quotes the original un-NAT'd source"
    );
    assert_eq!(
        &quoted_ip[16..20],
        &REMOTE_IP,
        "quotes the original destination"
    );
    let quoted_udp = &icmp[28..36];
    assert_eq!(
        &quoted_udp[0..2],
        &51_000_u16.to_be_bytes(),
        "quotes the original source port"
    );
    assert_eq!(&quoted_udp[2..4], &53_u16.to_be_bytes());
}

#[test]
fn host_unreachable_after_max_arp_attempts_generates_exact_type3_code1() {
    let scenario = Scenario {
        name: "host_unreachable_after_max_arp_attempts",
        config_toml: DIRECT_WAN_ROUTE,
        generation: 7,
        seed: 11,
        ticks: vec![
            ScenarioTick {
                now: MonotonicMillis(0),
                ingress: vec![ScenarioIngress::new(
                    LAN,
                    udp_frame(
                        LAN_HOP,
                        HOST_IP,
                        UNREACHABLE_HOST_IP,
                        51_000,
                        9_999,
                        64,
                        b"probe",
                    ),
                )],
            },
            ScenarioTick {
                now: MonotonicMillis(1_000),
                ingress: vec![],
            },
            ScenarioTick {
                now: MonotonicMillis(2_000),
                ingress: vec![],
            },
            ScenarioTick {
                now: MonotonicMillis(3_000),
                ingress: vec![],
            },
        ],
    };
    let outcomes = run_scenario(&scenario).expect("scenario drives to completion");
    assert_eq!(outcomes.len(), 4);
    for outcome in &outcomes {
        assert!(outcome.active);
        assert_eq!(outcome.publication, PublicationSummary::Unchanged);
    }

    // Attempts 1..3: the router broadcasts an ARP request for the
    // unresolvable directly-connected host once per retry interval. No
    // neighbor ever answers.
    for (index, outcome) in outcomes[0..3].iter().enumerate() {
        assert_eq!(
            outcome.tx.len(),
            1,
            "tick {index} sends exactly one ARP request"
        );
        let arp = &outcome.tx[0];
        assert_eq!(arp.egress, WAN);
        assert_eq!(&arp.bytes[0..6], &[0xff; 6], "broadcast destination");
        assert_eq!(&arp.bytes[6..12], &WAN_MAC, "router originates the request");
        assert_eq!(
            &arp.bytes[12..14],
            &0x0806_u16.to_be_bytes(),
            "ARP ethertype"
        );
        assert_eq!(
            &arp.bytes[20..22],
            &1_u16.to_be_bytes(),
            "ARP request opcode"
        );
        assert_eq!(&arp.bytes[22..28], &WAN_MAC);
        assert_eq!(&arp.bytes[28..32], &WAN_IP);
        assert_eq!(&arp.bytes[38..42], &UNREACHABLE_HOST_IP, "target IP");
    }

    // The third attempt's own timeout at t=3000 exhausts max-attempts=3,
    // moving resolution to Failed and dispatching the held failure to the
    // ICMPv4 error queue; the generated-ICMPv4 phase transmits it in the
    // same tick.
    let final_tick = &outcomes[3];
    assert_eq!(
        final_tick.tx.len(),
        1,
        "the router generates one ICMPv4 host-unreachable reply"
    );
    let reply = &final_tick.tx[0];
    assert_eq!(reply.ingress, LAN);
    assert_eq!(
        reply.egress, LAN,
        "the reply returns out the original ingress interface"
    );
    assert_eq!(reply.origin, FrameOrigin::Generated);
    assert_eq!(
        &reply.bytes[0..6],
        &HOST_MAC,
        "back to the original sender, using the already-known static neighbor"
    );
    assert_eq!(&reply.bytes[6..12], &LAN_MAC);
    let ip = &reply.bytes[14..34];
    assert_eq!(ip[9], 1, "ICMP protocol");
    assert_eq!(
        &ip[12..16],
        &LAN_IP,
        "the router originates the error itself"
    );
    assert_eq!(
        &ip[16..20],
        &HOST_IP,
        "addressed back to the original sender"
    );
    let icmp = &reply.bytes[34..];
    assert_eq!(icmp[0], 3, "ICMPv4 type 3: destination unreachable");
    assert_eq!(icmp[1], 1, "code 1: host unreachable");
    let quoted_ip = &icmp[8..28];
    assert_eq!(quoted_ip[9], 17, "quotes the original UDP protocol");
    assert_eq!(&quoted_ip[12..16], &HOST_IP, "quotes the original source");
    assert_eq!(
        &quoted_ip[16..20],
        &UNREACHABLE_HOST_IP,
        "quotes the original unresolvable destination"
    );
    let quoted_udp = &icmp[28..36];
    assert_eq!(
        &quoted_udp[0..2],
        &51_000_u16.to_be_bytes(),
        "quotes the original source port"
    );
    assert_eq!(&quoted_udp[2..4], &9_999_u16.to_be_bytes());
}

#[test]
fn identical_scenario_replay_is_byte_and_order_identical() {
    let scenario = one_tick_scenario(
        "replay_determinism",
        UDP_NAT,
        11,
        LAN,
        udp_frame(LAN_HOP, HOST_IP, REMOTE_IP, 51_000, 53, 64, b"query"),
    );
    let first = run_scenario(&scenario).expect("first run drives to completion");
    let second = run_scenario(&scenario).expect("second run drives to completion");
    assert_eq!(first, second, "byte-and-order-identical replay");
}

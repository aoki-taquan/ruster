//! Shared fixture for the observability integration tests.

#![allow(dead_code)]

use std::num::NonZeroU64;

use ruster_core::{
    internet_checksum, ipv4_header_checksum, FirewallConfig, FirewallHashKey, FirewallPolicy,
    ForwardingSnapshot, Icmpv4ErrorRuntime, IfId, Interface, Ipv4Address, LocalIpv4Binding,
    MacAddress, Nat44TcpConfig, Nat44TcpPolicy, Nat44UdpConfig, Nat44UdpPolicy,
    PublicationQuiescenceGuard, ResolutionRuntime, Route,
};
use ruster_io_sim::SimIo;
use ruster_runtime::{
    FirewallServiceView, FullServicePublication, FullServiceView, Nat44TcpServiceView,
    Nat44UdpServiceView, PublicationTick,
};

pub const LAN: IfId = IfId(1);
pub const WAN: IfId = IfId(2);
pub const LAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);
pub const WAN_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
pub const HOST_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 50]);
pub const LAN_IP: [u8; 4] = [10, 0, 0, 1];
pub const HOST_IP: [u8; 4] = [10, 0, 0, 50];
pub const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 10]);

/// Only the LAN prefix is routed, so other destinations are route misses.
pub fn routes() -> [Route; 1] {
    [Route::new(Ipv4Address::from_octets([10, 0, 0, 0]), 24, LAN, None).unwrap()]
}

pub const INTERFACES: [Interface; 2] = [
    Interface {
        id: LAN,
        mac: LAN_MAC,
    },
    Interface {
        id: WAN,
        mac: WAN_MAC,
    },
];

pub const BINDINGS: [LocalIpv4Binding; 2] = [
    LocalIpv4Binding {
        interface: LAN,
        address: Ipv4Address::from_octets(LAN_IP),
    },
    LocalIpv4Binding {
        interface: WAN,
        address: PUBLIC,
    },
];

pub fn udp_config(snapshot: &ForwardingSnapshot<'_>) -> Nat44UdpConfig {
    Nat44UdpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44UdpPolicy::default(),
    )
    .unwrap()
}

pub fn tcp_config(snapshot: &ForwardingSnapshot<'_>) -> Nat44TcpConfig {
    Nat44TcpConfig::new(
        snapshot,
        LAN,
        WAN,
        PUBLIC,
        40_000,
        40_000,
        Nat44TcpPolicy::default(),
    )
    .unwrap()
}

pub fn firewall_config<'a>(snapshot: &ForwardingSnapshot<'a>) -> FirewallConfig<'a> {
    FirewallConfig::new(
        snapshot,
        &[],
        FirewallPolicy::default(),
        1,
        FirewallHashKey::new(1, 2).unwrap(),
    )
    .unwrap()
}

/// Minimal publication: candidates are successor generations; a candidate
/// that does not increase the generation is rejected.
pub struct Publication<'view, 'storage> {
    pub generation: NonZeroU64,
    pub snapshot: &'view ForwardingSnapshot<'storage>,
    pub resolution: &'view mut ResolutionRuntime<'storage>,
    pub icmpv4_errors: &'view mut Icmpv4ErrorRuntime<'storage>,
    pub udp_config: Nat44UdpConfig,
    pub tcp_config: Nat44TcpConfig,
    pub firewall_config: FirewallConfig<'storage>,
}

impl<'storage> FullServicePublication<'storage, SimIo> for Publication<'_, 'storage> {
    type Candidate = NonZeroU64;
    type Reject = &'static str;

    fn publish_candidate(
        &mut self,
        candidate: NonZeroU64,
        _quiescence: PublicationQuiescenceGuard<'_, SimIo>,
        _tick: &PublicationTick<'_>,
    ) -> Result<(), Self::Reject> {
        if candidate <= self.generation {
            return Err("generation not increasing");
        }
        self.generation = candidate;
        Ok(())
    }

    fn active(&mut self, _tick: &PublicationTick<'_>) -> Option<FullServiceView<'_, 'storage>> {
        Some(FullServiceView::new(
            self.generation,
            *self.snapshot,
            self.resolution,
            self.icmpv4_errors,
            Nat44UdpServiceView::new(self.udp_config, None),
            Nat44TcpServiceView::new(self.tcp_config, None),
            FirewallServiceView::new(self.firewall_config, None),
        ))
    }
}

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(128);
    frame.extend_from_slice(&LAN_MAC.0);
    frame.extend_from_slice(&HOST_MAC.0);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame
}

/// A valid IPv4 packet from the LAN host to `destination`.
pub fn ipv4(protocol: u8, destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut frame = ethernet(0x0800);
    let total = u16::try_from(20 + payload.len()).unwrap().to_be_bytes();
    let mut header = [
        0x45,
        0,
        total[0],
        total[1],
        0,
        1,
        0x40,
        0,
        64,
        protocol,
        0,
        0,
        HOST_IP[0],
        HOST_IP[1],
        HOST_IP[2],
        HOST_IP[3],
        destination[0],
        destination[1],
        destination[2],
        destination[3],
    ];
    let checksum = ipv4_header_checksum(&header).to_be_bytes();
    header[10..12].copy_from_slice(&checksum);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame
}

pub fn truncated_ethernet() -> Vec<u8> {
    vec![0; 10]
}

pub fn unsupported_ethertype() -> Vec<u8> {
    let mut frame = ethernet(0x86dd);
    frame.extend_from_slice(&[0; 40]);
    frame
}

pub fn bad_ipv4_checksum() -> Vec<u8> {
    let mut frame = ipv4(17, LAN_IP, &[0; 8]);
    frame[24] ^= 0xff;
    frame
}

/// UDP to the router's own LAN address: consumed as local-unsupported.
pub fn local_udp() -> Vec<u8> {
    ipv4(
        17,
        LAN_IP,
        &[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00],
    )
}

/// ICMPv4 Echo Request to the router's LAN address: answered in place.
pub fn echo_request() -> Vec<u8> {
    let mut icmp = [8, 0, 0, 0, 0x12, 0x34, 0, 1, 0xaa, 0xbb];
    let checksum = internet_checksum(&icmp).to_be_bytes();
    icmp[2..4].copy_from_slice(&checksum);
    ipv4(1, LAN_IP, &icmp)
}

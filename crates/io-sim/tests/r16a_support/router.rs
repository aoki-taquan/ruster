//! Shared R16 router topology rendered as `ruster-config` V1 TOML.
//!
//! LAN 192.168.1.0/24 (hosts .10-.13, static neighbors) sits behind UDP/TCP
//! NAPT on WAN 203.0.113.2. Remote servers 198.51.100.0/24 (and optionally
//! 192.0.2.0/24) are reached via the static WAN gateway 203.0.113.1. The
//! firewall denies LAN->WAN UDP/9 and TCP/23 and statefully allows other
//! LAN->WAN UDP/TCP. The document is built by the test, never copied.

use std::fmt::Write;

use ruster_config::{parse, validate, ValidatedConfig, ValidatedConfigV1, ValidationLimits};
use ruster_core::{Ipv4Address, MacAddress};

use super::targets::CaseFailure;

pub const LAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x01]);
pub const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x02]);
pub const GATEWAY_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0xfe]);
pub const PUBLIC: Ipv4Address = Ipv4Address::from_octets([203, 0, 113, 2]);
pub const HOSTS: usize = 4;
pub const REMOTES: usize = 4;
pub const PORT_FIRST: u16 = 40_000;
pub const UDP_DENIED_PORT: u16 = 9;
pub const TCP_DENIED_PORT: u16 = 23;
/// Destination port the publication `deny-dns` variant additionally denies.
pub const UDP_VARIANT_DENIED_PORT: u16 = 53;

pub const LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 12,
    max_runtime_bytes: 16 << 20,
};

pub fn host(index: usize) -> Ipv4Address {
    Ipv4Address::from_octets([192, 168, 1, 10 + u8::try_from(index % HOSTS).unwrap()])
}

pub fn host_mac(index: usize) -> MacAddress {
    MacAddress([
        0x02,
        0,
        0,
        0,
        0,
        0x10 + u8::try_from(index % HOSTS).unwrap(),
    ])
}

/// Remote server `index`; `alternate` selects the optional 192.0.2.0/24 net.
pub fn remote(index: usize, alternate: bool) -> Ipv4Address {
    let last = 20 + u8::try_from(index % REMOTES).unwrap();
    if alternate {
        Ipv4Address::from_octets([192, 0, 2, last])
    } else {
        Ipv4Address::from_octets([198, 51, 100, last])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouterParams {
    pub udp_mappings: u32,
    pub udp_peers: u32,
    pub tcp_mappings: u32,
    pub tcp_sessions: u32,
    pub firewall_states: u32,
    /// Number of public ports, starting at [`PORT_FIRST`].
    pub ports: u16,
    pub alternate_route: bool,
    pub deny_dns: bool,
    pub resolution_interval_ms: u64,
    pub icmpv4_interval_ms: u64,
    pub wan_mac_last: u8,
    pub include_nat: bool,
    pub offlink_route: bool,
}

impl RouterParams {
    pub const BASE: Self = Self {
        udp_mappings: 8,
        udp_peers: 8,
        tcp_mappings: 8,
        tcp_sessions: 8,
        firewall_states: 16,
        ports: 16,
        alternate_route: false,
        deny_dns: false,
        resolution_interval_ms: 1_000,
        icmpv4_interval_ms: 100,
        wan_mac_last: 0x02,
        include_nat: true,
        offlink_route: false,
    };

    pub fn port_last(self) -> u16 {
        PORT_FIRST + self.ports - 1
    }

    pub fn wan_mac(self) -> MacAddress {
        MacAddress([0x02, 0, 0, 0, 0, self.wan_mac_last])
    }

    pub fn render(self) -> String {
        let mut out = String::with_capacity(4_096);
        let wan = self.wan_mac_last;
        let _ = write!(
            out,
            "schema-version = 1\n\n\
             [[interfaces]]\nid = 1\nname = \"lan\"\ndevice = \"sim0\"\nmac = \"02:00:00:00:00:01\"\n\n\
             [[interfaces]]\nid = 2\nname = \"wan\"\ndevice = \"sim1\"\nmac = \"02:00:00:00:00:{wan:02x}\"\n\n\
             [[addresses]]\ninterface = \"lan\"\nipv4 = \"192.168.1.1/24\"\n\n\
             [[addresses]]\ninterface = \"wan\"\nipv4 = \"203.0.113.2/24\"\n\n\
             [[routes]]\nprefix = \"198.51.100.0/24\"\negress = \"wan\"\nvia = \"203.0.113.1\"\n\n"
        );
        if self.alternate_route {
            out.push_str(
                "[[routes]]\nprefix = \"192.0.2.0/24\"\negress = \"wan\"\nvia = \"203.0.113.1\"\n\n",
            );
        }
        if self.offlink_route {
            out.push_str(
                "[[routes]]\nprefix = \"10.9.0.0/16\"\negress = \"wan\"\nvia = \"10.200.0.1\"\n\n",
            );
        }
        for index in 0..HOSTS {
            let _ = write!(
                out,
                "[[neighbors]]\ninterface = \"lan\"\naddress = \"192.168.1.{}\"\nmac = \"02:00:00:00:00:{:02x}\"\n\n",
                10 + index,
                0x10 + index
            );
        }
        out.push_str(
            "[[neighbors]]\ninterface = \"wan\"\naddress = \"203.0.113.1\"\nmac = \"02:00:00:00:00:fe\"\n\n\
             [ipv4-origin]\ndefault-ttl = 64\n\n",
        );
        let _ = write!(
            out,
            "[resolution.policy]\ninterval-ms = {}\nstate-ttl-ms = 3000\n\
             dynamic-neighbor-ttl-ms = 60000\nmax-attempts = 3\n\n\
             [resolution.capacity]\nstates = 8\nactions = 8\ndynamic-neighbors = 8\nfailure-holds = 8\n\n\
             [icmpv4-errors.policy]\ninterval-ms = {}\nstate-ttl-ms = 60000\n\n\
             [icmpv4-errors.capacity]\nstates = 8\nactions = 8\n\n",
            self.resolution_interval_ms, self.icmpv4_interval_ms
        );
        if self.include_nat {
            let _ = write!(
                out,
                "[nat44.realm]\ninside = \"lan\"\noutside = \"wan\"\npublic-address = \"203.0.113.2\"\n\n\
                 [nat44.realm.ports]\nfirst = {}\nlast = {}\n\n\
                 [nat44.udp]\nidle-ttl-ms = 300000\nallocator-seed = \"11\"\nicmpv4-errors = \"disabled\"\n\n\
                 [nat44.udp.capacity]\nmappings = {}\npeers = {}\n\n\
                 [nat44.tcp]\nidle-ttl-ms = 7440000\nallocator-seed = \"12\"\nicmpv4-errors = \"disabled\"\n\n\
                 [nat44.tcp.capacity]\nmappings = {}\nsessions = {}\n\n",
                PORT_FIRST,
                self.port_last(),
                self.udp_mappings,
                self.udp_peers,
                self.tcp_mappings,
                self.tcp_sessions
            );
        }
        let _ = write!(
            out,
            "[firewall.policy]\nudp-idle-ttl-ms = 300000\ntcp-opening-idle-ttl-ms = 240000\n\
             tcp-active-idle-ttl-ms = 7440000\n\n\
             [firewall.capacity]\nstates = {}\n\n",
            self.firewall_states
        );
        let mut rule = |id: u32, protocol: &str, action: &str, ports: (u16, u16)| {
            let _ = write!(
                out,
                "[[firewall.rules]]\nid = {id}\ningress = \"lan\"\negress = \"wan\"\n\
                 source = \"192.168.1.0/24\"\ndestination = \"0.0.0.0/0\"\n\
                 protocol = \"{protocol}\"\naction = \"{action}\"\n\n\
                 [firewall.rules.source-ports]\nfirst = 0\nlast = 65535\n\n\
                 [firewall.rules.destination-ports]\nfirst = {}\nlast = {}\n\n",
                ports.0, ports.1
            );
        };
        rule(10, "tcp", "deny", (TCP_DENIED_PORT, TCP_DENIED_PORT));
        rule(11, "udp", "deny", (UDP_DENIED_PORT, UDP_DENIED_PORT));
        if self.deny_dns {
            rule(
                12,
                "udp",
                "deny",
                (UDP_VARIANT_DENIED_PORT, UDP_VARIANT_DENIED_PORT),
            );
        }
        rule(20, "udp", "allow-stateful", (1, 65535));
        rule(30, "tcp", "allow-stateful", (1, 65535));
        out.push_str(
            "[tick]\nrx = 32\nresolution-timer-scans = 16\nfailure-dispatch-scans = 16\n\
             generated-arp = 8\ngenerated-icmpv4 = 8\n",
        );
        out
    }

    /// Parses and validates the rendered document.
    pub fn validated(self) -> Result<ValidatedConfigV1, CaseFailure> {
        let parsed = parse(self.render().as_bytes())
            .map_err(|error| CaseFailure::new(format!("router config parse: {error:?}")))?;
        match validate(parsed, LIMITS)
            .map_err(|error| CaseFailure::new(format!("router config validate: {error:?}")))?
        {
            ValidatedConfig::V1(config) => Ok(config),
            _ => Err(CaseFailure::new("router config has an unknown version")),
        }
    }
}

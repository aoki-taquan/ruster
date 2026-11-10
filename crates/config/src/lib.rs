//! The router's configuration in its two forms, `ruster.toml` and the lock form.
//!
//! `ruster.toml` is what people write: it may leave out a value that has a default
//! or that follows from other settings. The lock form spells out every parameter;
//! nothing in it is optional, and it carries a format version. [`resolve`] turns
//! the first into the second, [`parse_lock`] reads the lock form and
//! [`Lock::to_text`] writes it. The processes take the lock form only and hold no
//! defaults: those are all here.
//!
//! The lock form holds the defaults and the values that follow from the
//! configuration alone (a VLAN's MTU from its parent's). What depends on values
//! found at run time (the firewall's outside from the default routes, MAP-E's
//! address from the delegated prefix) is still worked out by the process.
//!
//! # `ruster.toml`
//!
//! ```toml
//! firewall-filtering = "endpoint-independent"  # optional: who outside
//!                              # may reach an inside host's UDP or TCP port that has a
//!                              # flow out, where no rule decides; the default, or
//!                              # "address-dependent", "address-and-port-dependent".
//!                              # Outside are NAT's outside and the interfaces of the
//!                              # default routes; inside, the other interfaces
//! firewall-outside = ["wan"]   # optional: the outside interfaces, when
//!                              # those are not right (a default route from a routing
//!                              # daemon, say)
//!
//! [[interface]]
//! name = "lan"                 # the FE port (the Linux device name)
//! mac = "02:00:00:00:00:01"
//! mtu = 1500                   # optional, 1500 when left out
//! enabled = true               # optional, true when left out
//! ipv4 = "192.0.2.1/24"        # optional
//! ipv6 = ["2001:db8:1::1/64"]  # optional; a link-local address is added by itself
//! vrf = "red"                  # optional, "default" when left out
//!
//! [[interface]]                # a WAN port whose IPv4 address a DHCP client finds
//! name = "wan"
//! mac = "02:00:00:00:00:02"
//! ipv4-from = "dhcp-wan"       # optional, instead of ipv4: the source (of kind
//!                              # dhcp-client) that sends the address
//!
//! [[interface]]                # a LAN port numbered from a delegated prefix
//! name = "lan2"
//! mac = "02:00:00:00:00:03"
//! ipv6-from = { source = "dhcp6-wan", subnet = 1 }  # optional: the /64 of subnet
//!                              # ID 1 in the prefix the source (of kind
//!                              # dhcpv6-client) has delegated, with the router at
//!                              # ::1 in it; besides any ipv6 given
//!
//! [[interface]]                # a VLAN sub-interface of lan, after lan
//! name = "lan.10"
//! parent = "lan"
//! vlan = 10                    # 1 to 4094
//! ipv4 = "10.10.0.1/24"        # mac is lan's and mtu lan's less 4 when left out
//!
//! [[interface]]                # an IPv4 in IPv6 tunnel (DS-Lite softwire)
//! name = "dslite"
//! tunnel = { local = "2001:db8:1::2", remote = "2001:db8:ff::1" }
//! ipv4 = "192.0.0.2/29"        # optional; this, the B4's address, when left out
//! # mtu is 1460 and mac 02:00:00:00:00:fe when left out
//!
//! [[interface]]                # a PPPoE session, there while the session is up
//! name = "ppp"
//! pppoe = { parent = "lan", source = "pppoe-wan" }  # the source (of kind pppoe)
//!                              # that sends the session and its IPv4 address
//! # mac is the parent's and mtu its less 8 when left out; no ipv4
//!
//! [map-e]                      # a MAP-E CE (instead of [nat] and a tunnel)
//! interface = "map"            # the tunnel interface it makes
//! inside = "lan"               # the NAT's inside
//! prefix = "2001:db8:12:3400::/56"  # the delegated (end-user) IPv6 prefix, or
//! # prefix-from = "dhcp6-wan"  # the source (of kind dhcpv6-client) that has it
//! rule-ipv6 = "2001:db8::/40"  # the Basic Mapping Rule
//! rule-ipv4 = "192.0.2.0/24"
//! ea-length = 16
//! psid-offset = 6              # optional, 6 when left out
//! br = "2001:db8:ffff::1"
//! mtu = 1460                   # optional, 1460 when left out
//! filtering = "endpoint-independent"  # optional, as for [nat]
//!
//! [[route]]
//! prefix = "0.0.0.0/0"         # or an IPv6 prefix such as "::/0"
//! interface = "wan"
//! via = "198.51.100.1"         # optional; left out for an on-link route
//! vrf = "default"              # optional; the interface may be in another VRF
//!
//! [[route]]                    # look the destination up again in another VRF
//! vrf = "red"
//! prefix = "0.0.0.0/0"
//! lookup-vrf = "default"
//!
//! [[route]]                    # drop the prefix's packets (a longer route still wins)
//! prefix = "10.0.0.0/8"
//! action = "discard"           # silently; "reject": with a Destination Unreachable
//!
//! [[firewall]]                 # forward rules of the default VRF, first match wins
//! action = "accept"            # or "drop"; an accepted flow's replies pass too
//! protocol = "udp"             # "tcp", "udp", "icmp" (IPv4) or "icmpv6" (IPv6)
//! ingress = "lan"              # optional, any interface when left out (and then
//!                              # also what other VRFs look up in this one);
//!                              # "rt-default" is the router itself: as ingress its own
//!                              # packets, as egress the packets to it (SSH, ping, ...)
//! egress = "wan"               # optional
//! source = "192.0.2.0/24"      # optional, any address when left out; IPv4 or IPv6
//! destination = "0.0.0.0/0"    # optional, of the source's family
//! # A tcp or udp rule with neither source nor destination is for IPv4 and IPv6.
//! source-ports = "1024-65535"  # optional, tcp and udp only; any when left out
//! destination-ports = "53"     # optional
//!
//! [icmp-errors]                # optional: the rate limits of the ICMP errors the
//! ipv4-interval-ms = 100       # router sends: one per this per egress and kind
//! ipv6-burst = 10              # (RFC 1812 4.3.2.8), and for ICMPv6 this many at
//! ipv6-interval-ms = 10        # once and one more every this (RFC 4443 2.4(f));
//!                              # these when left out
//!
//! [nat]                        # NAPT of the default VRF
//! inside = "lan"
//! outside = "wan"              # must have an ipv4 address: the public one
//! ports = "1024-32767"         # optional, 1024-32767 when left out
//! external = "198.51.100.2"    # optional; for now only the outside's own address
//! filtering = "endpoint-independent"  # optional, the default, or
//!                              # "address-dependent", "address-and-port-dependent"
//! ipv4-id-rate-limit = true    # optional, the default: datagrams that may be
//!                              # fragmented are dropped above the rate at which
//!                              # their IPv4 IDs stay unique for 120 s (about 550
//!                              # a second to one destination, shared by the LAN);
//!                              # false lets them go (also in [map-e])
//! ports-per-host = 0           # optional: the most public ports one LAN host
//!                              # holds for each of UDP, TCP and ICMP; 0 for none
//! state-per-host = 0           # optional: the most TCP sessions, and outside
//!                              # endpoints of its UDP (not with endpoint-
//!                              # independent filtering) and ICMP, of one LAN host
//!                              # (both also in [map-e]; setting or lowering one
//!                              # drops every NAT flow)
//!
//! [dns]                        # optional: the DNS server for the LAN (Unbound,
//!                              # through ruster-unbound)
//! upstream = ["192.0.2.53"]    # optional: the servers it forwards every query to;
//!                              # when left out it resolves from the root itself
//! listen = ["lan.10"]          # optional: the interfaces of the default VRF it
//!                              # answers on; when left out, the inside of [nat] or
//!                              # [map-e] (one of them, or listen, must be given)
//!
//! [[dhcp]]                     # optional: a DHCP server (Kea, through ruster-kea)
//!                              # for one interface; one [[dhcp]] per interface
//! interface = "lan"            # a port or VLAN of the default VRF with an ipv4
//!                              # address, which is the relay's and gives the subnet
//! pool = "192.0.2.100-192.0.2.199"  # the addresses it leases, in the subnet
//! lease-time = 3600            # optional, in seconds; 3600 when left out
//! router = ["192.0.2.1"]       # optional: the routers option; the interface's
//!                              # address when left out
//! dns = ["192.0.2.1"]          # optional: the DNS servers option; when left out,
//!                              # the interface's address if [dns] listens on it,
//!                              # else none
//! punt-rate = 200              # optional: how many DHCP packets a second the FE
//! punt-burst = 100             # hands ruster-kea from the interface, and at once;
//!                              # these when left out
//!
//! [[dhcp6]]                    # optional: a DHCPv6 server (Kea, through
//!                              # ruster-kea) for one interface; one per interface
//! interface = "lan"            # a port or VLAN of the default VRF with a global
//!                              # ipv6 address; the first is the relay's
//!                              # link-address and gives the subnet
//! pool = "2001:db8:1::1000-2001:db8:1::1fff"  # the addresses it leases
//! preferred-lifetime = 3600    # optional, seconds; these when left out
//! valid-lifetime = 7200
//! dns = ["2001:db8:1::1"]      # optional: the DNS servers option; when left out,
//!                              # the interface's addresses [dns] listens on
//! punt-rate = 200              # optional, as in [[dhcp]]
//! punt-burst = 100
//!
//! [[ra]]                       # optional: Router Advertisements (neighd) on one
//!                              # interface; one [[ra]] per interface. They
//!                              # advertise the prefixes of the interface's /64
//!                              # addresses (not link-local), on-link and for SLAAC
//! interface = "lan"
//! max-interval = 600           # optional, seconds; RFC 4861 6.2.1's defaults:
//! min-interval = 198           # 0.33 of max-interval (0.75 below 9 s)
//! router-lifetime = 1800       # 3 times max-interval; 0: not a default router
//! hop-limit = 64
//! managed = false              # M: addresses from DHCPv6
//! other = false                # O: other settings from DHCPv6
//! mtu = 1500                   # an MTU option; none when left out
//! reachable-time = 0           # milliseconds; 0: unspecified
//! retrans-timer = 0
//! valid-lifetime = 2592000     # of each prefix, seconds
//! preferred-lifetime = 604800
//! dns = ["2001:db8:1::1"]      # a Recursive DNS Server option (RFC 8106); when
//!                              # left out, the interface's addresses [dns]
//!                              # listens on, else none
//! dns-lifetime = 1800          # 3 times max-interval
//!
//! [[pppoe]]                    # optional: a PPPoE client (ruster-pppoed) for one
//!                              # source, so for the interface that names it
//! source = "pppoe-wan"
//! user = "user@isp.example"
//! password = "secret"
//! service = ""                 # optional: the service name; empty for any
//! ac-name = "ac1"              # optional: take offers only from this AC
//! ipv6 = true                  # optional, true: run IPv6CP too
//! echo-interval = 10           # optional, 10: seconds between LCP Echo-Requests;
//!                              # 0 for none
//! echo-failures = 3            # optional, 3: unanswered ones that end the session
//! default-route = false        # optional, false: the IPv4 default route out of
//!                              # the session, to ribd as source pppoed
//!
//! [[dhcp-client]]              # optional: the WAN side's DHCP client
//!                              # (ruster-dhcpc) on one port or VLAN
//! interface = "wan"
//! ipv4-source = "dhcp-wan"     # optional: run DHCPv4, sending the lease to this
//!                              # source (of kind dhcp-client); the interface's
//!                              # ipv4-from when left out
//! ipv6-source = "dhcp6-wan"    # optional: run DHCPv6 and ask for a delegated
//!                              # prefix, sending to this source (dhcpv6-client)
//! ipv6-address = false         # optional, false: ask DHCPv6 for an address too
//! default-route = true         # optional, true: to ribd as source dhcpc, the IPv4
//!                              # default route via the router option, and the
//!                              # IPv6 one via the address DHCPv6 replies come from
//! punt-rate = 20               # optional, as in [[dhcp]]; these when left out
//! punt-burst = 20
//! [bgp]                        # optional: BGP in the default VRF (FRR's bgpd,
//!                              # through ruster-frr)
//! as = 65001                   # the router's AS number
//! router-id = "198.51.100.1"   # optional: the first ipv4 address of the default
//!                              # VRF's enabled interfaces when left out
//! networks = ["203.0.113.0/24", "2001:db8:5::/48"]  # optional: the prefixes it
//!                              # announces, always (FRR sees no route of the FE)
//! include = "/etc/ruster/frr-extra.conf"  # optional: FRR settings that ruster-frr
//!                              # adds to FRR's configuration as they are
//!
//! [[bgp.neighbor]]
//! address = "198.51.100.10"    # on the subnet of one of the default VRF's
//!                              # interfaces; the session carries the unicast
//!                              # routes of its family (IPv4 or IPv6)
//! remote-as = 65002
//! description = "upstream"     # optional
//!
//! [[source]]                   # optional: a daemon that sends confd values found
//!                              # at run time, on confd/source/<name>.sock
//! name = "pppoe-wan"           # lower-case letters, digits and -, from a letter
//! kind = "pppoe"               # what it may send: "pppoe" (ruster-pppoed: a
//!                              # session, its IPv4 address and DNS servers),
//!                              # "dhcp-client" (an IPv4 address and DNS servers),
//!                              # "dhcpv6-client" (an IPv6 address, a delegated
//!                              # prefix and DNS servers)
//! sync-wait = 10               # optional: after confd starts, the most seconds
//!                              # it waits for the source to send everything again;
//!                              # by kind when left out (10 for each)
//! ```
//!
//! # The lock form
//!
//! The same settings with every key given. A value there may be none or one of
//! is a list (`ipv4 = []`, `via = ["198.51.100.1"]`, `nat = []`); an empty list
//! means there is none, and for a firewall match, that it matches anything. An
//! interface's `kind` and a route's `target` say what it is.
//!
//! ```toml
//! version = 1
//! firewall-filtering = "endpoint-independent"
//! firewall-outside = "derive"  # NAT's outside and the default routes', or a list
//! map-e = []                   # a [[map-e]] has all of [map-e]'s keys, and
//!                              # mac = "02:00:00:00:00:fe" and ports = "1024-32767"
//!                              # (the NAT's ports when the address is not shared);
//!                              # prefix and prefix-from are lists of none or one
//!
//! [icmp-errors]
//! ipv4-interval-ms = 100
//! ipv6-burst = 10
//! ipv6-interval-ms = 10
//!
//! [[interface]]
//! name = "lan"
//! mac = "02:00:00:00:00:01"
//! mtu = 1500
//! enabled = true
//! vrf = "default"
//! ipv4 = ["192.0.2.1/24"]
//! ipv4-from = []               # none or one source; then ipv4 is empty
//! ipv6 = []
//! ipv6-from = []               # none or one: [{ source = "dhcp6-wan", subnet = 1 }]
//! kind = "port"
//!
//! [[interface]]
//! name = "lan.10"
//! mac = "02:00:00:00:00:01"
//! mtu = 1496
//! enabled = true
//! vrf = "default"
//! ipv4 = []
//! ipv4-from = []
//! ipv6 = []
//! ipv6-from = []
//!
//! [interface.kind.vlan]        # or [interface.kind.tunnel] with local and remote,
//! parent = "lan"               # [interface.kind.pppoe] with parent and source
//! id = 10
//!
//! [[nat]]
//! inside = "lan.10"
//! outside = "lan"
//! ports = "1024-32767"
//! external = []                # the outside's own address
//! filtering = "endpoint-independent"
//! ipv4-id-rate-limit = true
//! ports-per-host = 0
//! state-per-host = 0
//!
//! [[route]]
//! vrf = "default"
//! prefix = "10.0.0.0/8"
//! target = "discard"           # or "reject"
//!
//! [[route]]
//! vrf = "default"
//! prefix = "0.0.0.0/0"
//!
//! [route.target.forward]       # or [route.target] with lookup-vrf = "red"
//! interface = "lan"
//! via = ["192.0.2.254"]
//!
//! [[firewall]]
//! action = "accept"
//! protocol = "udp"
//! ingress = ["lan"]
//! egress = []
//! source = []
//! destination = []
//! source-ports = []
//! destination-ports = ["53"]
//!
//! [[dns]]                      # none or one
//! listen = ["192.0.2.1"]       # the router's addresses it answers on: those of the
//!                              # listen interfaces (not link-local ones)
//! allow = ["192.0.2.0/24"]     # the clients it answers: their prefixes
//! upstream = ["192.0.2.53"]    # empty: it resolves from the root itself
//! upstream-from = []           # the sources whose DNS servers it uses too (a WAN
//!                              # DHCP client, say); none can be given yet
//!
//! [[dhcp]]
//! interface = "lan"
//! mac = "02:00:00:00:00:01"    # the interface's: the source of the frames to clients
//! address = "192.0.2.1/24"     # the interface's IPv4 address
//! pool = "192.0.2.100-192.0.2.199"
//! lease-time = 3600
//! router = ["192.0.2.1"]
//! dns = ["192.0.2.1"]
//! punt-rate = 200
//! punt-burst = 100
//!
//! [[dhcp6]]
//! interface = "lan"
//! mac = "02:00:00:00:00:01"
//! link-local = "fe80::ff:fe00:1"  # from mac: the source of the replies to clients
//! address = "2001:db8:1::1/64" # the interface's first global ipv6 address
//! pool = "2001:db8:1::1000-2001:db8:1::1fff"
//! preferred-lifetime = 3600
//! valid-lifetime = 7200
//! dns = []
//! punt-rate = 200
//! punt-burst = 100
//!
//! [[ra]]                       # the prefixes' lifetimes are in [[ra.prefix]]
//! interface = "lan"
//! min-interval = 198
//! max-interval = 600
//! router-lifetime = 1800
//! hop-limit = 64
//! managed = false
//! other = false
//! mtu = []                     # none or one
//! reachable-time = 0
//! retrans-timer = 0
//! dns = []
//! dns-lifetime = 1800
//! prefix-from = []             # the sources whose delegated prefixes it advertises
//!                              # too: the interface's ipv6-from source
//!
//! [[ra.prefix]]                # the interface's /64s, from its addresses
//! prefix = "2001:db8:1::/64"
//! on-link = true
//! autonomous = true
//! valid-lifetime = 2592000
//! preferred-lifetime = 604800
//!
//! [[source]]
//! name = "pppoe-wan"
//! kind = "pppoe"
//! sync-wait = 10
//!
//! [[pppoe]]
//! source = "pppoe-wan"
//! interface = "ppp"            # the session interface that names the source
//! vrf = "default"              # its VRF
//! parent = "lan"               # where the session runs
//! mac = "02:00:00:00:00:01"    # the session interface's MAC address
//! user = "user@isp.example"
//! password = "secret"
//! service = ""
//! ac-name = []
//! ipv6 = true
//! echo-interval = 10
//! echo-failures = 3
//! default-route = false
//!
//! [[dhcp-client]]
//! interface = "wan"
//! vrf = "default"
//! mac = "02:00:00:00:00:02"
//! link-local = "fe80::ff:fe00:2"
//! ipv4-source = ["dhcp-wan"]   # none or one
//! ipv6-source = []             # none or one
//! ipv6-address = false
//! default-route = true
//! punt-rate = 20
//! punt-burst = 20
//! [[bgp]]                      # none or one
//! as = 65001
//! router-id = "198.51.100.1"
//! networks = ["203.0.113.0/24"]
//! include = []                 # none or one
//!
//! [[bgp.neighbor]]
//! address = "198.51.100.10"
//! remote-as = 65002
//! description = []             # none or one
//! ```
//!
//! Text with another `version` is refused. A later version that removes a
//! parameter or changes its meaning gets a new number.
//!
//! # Standards
//!
//! - RFC 6243: the lock form is the configuration with its defaults reported, as
//!   `report-all` does. Deviation: it is TOML, not a YANG instance.
//! - RFC 8529 (`ietf-network-instance`): an interface or route with no VRF is in
//!   `default`.
//! - RFC 6333 section 5.7: a DS-Lite tunnel with no IPv4 address gets the B4's,
//!   192.0.0.2/29, if no earlier interface of its VRF has that address or its
//!   prefix (so only the first such tunnel of a VRF gets it).
//! - RFC 4861 section 6.2.1: `[[ra]]`'s defaults are the router configuration
//!   variables' (AdvCurHopLimit the IANA value for IPv6, 64). Deviations: below 9 s
//!   MinRtrAdvInterval is 0.75 of MaxRtrAdvInterval, not MaxRtrAdvInterval, which
//!   the same section's upper bound for it refuses; it is at least 3 s. RFC 4862 section 5.5.3: only the
//!   prefixes of /64 addresses are advertised (for SLAAC on Ethernet, RFC 2464). RFC
//!   8106 section 5.1: the DNS servers' lifetime is 3 times MaxRtrAdvInterval.
//! - RFC 6286 section 2.1: a BGP Identifier is a 32-bit number, written as an IPv4
//!   address; the default is one of the router's IPv4 addresses.
//! - RFC 4787 REQ-8 and RFC 5382 REQ-3: NAT and the firewall filter
//!   endpoint-independently by default.

mod bgp;
mod dhcp6;
mod dhcp_client;
mod ra;
mod resolve;

use serde::{Deserialize, Serialize};

pub use bgp::{frr_part, parse_frr_part, Bgp, BgpNeighbor, Connected};
pub use dhcp6::{link_local, Dhcp6, DHCP6_PREFERRED_LIFETIME, DHCP6_VALID_LIFETIME};
pub use dhcp_client::{
    dhcp_client_part, parse_dhcp_client_part, DhcpClient, DHCP_CLIENT_PUNT_BURST,
    DHCP_CLIENT_PUNT_RATE,
};
pub use ra::{
    parse_ra_part, ra_min_interval, ra_part, Ra, RaPrefix, RA_HOP_LIMIT, RA_MAX_INTERVAL,
    RA_PREFERRED_LIFETIME, RA_VALID_LIFETIME,
};
pub use resolve::resolve;

/// The lock form's version that this ruster reads and writes.
pub const VERSION: u32 = 1;

/// The MTU of an interface that names none, and the most the FE takes (frames of
/// up to 1514 bytes).
pub const MTU: u16 = 1_500;
/// What a VLAN tag takes from the parent's MTU.
pub const VLAN_OVERHEAD: u16 = 4;
/// What the PPPoE header takes from the parent's MTU (RFC 2516).
pub const PPPOE_OVERHEAD: u16 = 8;
/// What the outer IPv6 header takes from a tunnel's MTU.
pub const TUNNEL_OVERHEAD: u16 = 40;
/// The MTU of a tunnel or MAP-E that names none.
pub const TUNNEL_MTU: u16 = MTU - TUNNEL_OVERHEAD;
/// The MAC address of a tunnel that names none; it only names the tunnel inside
/// the FE.
pub const TUNNEL_MAC: &str = "02:00:00:00:00:fe";
/// A DS-Lite B4's address when it has none of its own (RFC 6333 section 5.7).
pub const B4_ADDRESS: &str = "192.0.0.2/29";
/// The NAT's ports: below Linux's default ephemeral ports (32768-60999), which the
/// router's own connections use.
pub const NAT_PORTS: &str = "1024-32767";
/// NAT's and the firewall's filtering.
pub const FILTERING: &str = "endpoint-independent";
/// MAP-E's PSID offset (RFC 7597 section 5.1).
pub const PSID_OFFSET: u8 = 6;
/// A DHCP lease's time, in seconds.
pub const DHCP_LEASE_TIME: u32 = 3_600;
/// How many DHCP packets per second, and at once, the FE hands over from one
/// interface. A client sends a few per lease; this leaves room for a LAN of a few
/// hundred starting together, and keeps a flood from one interface off the others'.
pub const DHCP_PUNT_RATE: u32 = 200;
pub const DHCP_PUNT_BURST: u32 = 100;

/// What a PPPoE client does when not told: run IPv6CP, an LCP Echo-Request every
/// 10 s, 3 unanswered end the session.
pub const PPPOE_ECHO_INTERVAL: u32 = 10;
pub const PPPOE_ECHO_FAILURES: u32 = 3;

/// The kinds of source, and how long confd waits after it starts for each to send
/// everything again, in seconds: a daemon in the same box connects again within a
/// second or two.
pub const SOURCE_KINDS: &[(&str, u32)] =
    &[("pppoe", 10), ("dhcp-client", 10), ("dhcpv6-client", 10)];
/// The ICMP error rate limits: IPv4's interval, and ICMPv6's burst and interval.
pub const ICMP_ERRORS: IcmpErrors = IcmpErrors {
    ipv4_interval_ms: 100,
    ipv6_burst: 10,
    ipv6_interval_ms: 10,
};

/// The configuration with every parameter given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Lock {
    pub version: u32,
    pub firewall_filtering: String,
    pub firewall_outside: FirewallOutside,
    pub icmp_errors: IcmpErrors,
    pub interface: Vec<Interface>,
    /// None or one.
    pub map_e: Vec<MapE>,
    /// None or one.
    pub nat: Vec<Nat>,
    pub route: Vec<Route>,
    pub firewall: Vec<FirewallRule>,
    /// None or one.
    pub dns: Vec<Dns>,
    /// One per interface.
    pub dhcp: Vec<Dhcp>,
    /// One per interface.
    pub dhcp6: Vec<Dhcp6>,
    /// One per interface.
    pub ra: Vec<Ra>,
    pub source: Vec<Source>,
    /// One per source of kind pppoe at most.
    pub pppoe: Vec<Pppoe>,
    /// One per interface.
    pub dhcp_client: Vec<DhcpClient>,
    /// None or one.
    pub bgp: Vec<Bgp>,
}

/// A PPPoE client (`ruster-pppoed`): the session it sets up for a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Pppoe {
    /// The source it writes the session to.
    pub source: String,
    /// The session interface, which names the source.
    pub interface: String,
    pub vrf: String,
    /// The port or VLAN the session runs on.
    pub parent: String,
    /// The session interface's MAC address.
    pub mac: String,
    pub user: String,
    pub password: String,
    pub service: String,
    /// None or one.
    pub ac_name: Vec<String>,
    pub ipv6: bool,
    /// Seconds; 0 for none.
    pub echo_interval: u32,
    pub echo_failures: u32,
    /// Whether to send ribd the IPv4 default route out of the session.
    pub default_route: bool,
}

/// A daemon that sends confd values found at run time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Source {
    pub name: String,
    /// One of [`SOURCE_KINDS`].
    pub kind: String,
    /// After confd starts, the most seconds it waits for the source to send
    /// everything again.
    pub sync_wait: u32,
}

/// The DHCP server for one interface: Kea, which `ruster-kea` configures and relays
/// to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Dhcp {
    pub interface: String,
    /// The interface's MAC address.
    pub mac: String,
    /// The interface's IPv4 address and prefix length.
    pub address: String,
    /// The first and last address leased, as `first-last`.
    pub pool: String,
    /// In seconds.
    pub lease_time: u32,
    /// The routers option.
    pub router: Vec<String>,
    /// The DNS servers option.
    pub dns: Vec<String>,
    /// The FE's rate limit on the DHCP it hands over from the interface: packets
    /// per second, and at once.
    pub punt_rate: u32,
    pub punt_burst: u32,
}

/// The DNS server for the LAN: Unbound, which `ruster-unbound` configures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Dns {
    /// The router's addresses it answers on.
    pub listen: Vec<String>,
    /// The prefixes of the clients it answers.
    pub allow: Vec<String>,
    /// The servers it forwards every query to; none: it resolves from the root.
    pub upstream: Vec<String>,
    /// The sources whose DNS servers it also forwards to, found at run time. None
    /// can be given yet.
    pub upstream_from: Vec<String>,
}

/// The firewall's outside interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OutsideText", into = "OutsideText")]
pub enum FirewallOutside {
    /// NAT's outside and the interfaces of the default routes, found at run time.
    Derive,
    Interfaces(Vec<String>),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum OutsideText {
    Word(String),
    List(Vec<String>),
}

impl TryFrom<OutsideText> for FirewallOutside {
    type Error = String;
    fn try_from(text: OutsideText) -> Result<Self, String> {
        match text {
            OutsideText::Word(word) if word == "derive" => Ok(Self::Derive),
            OutsideText::Word(_) => Err("firewall-outside must be \"derive\" or a list".into()),
            OutsideText::List(names) => Ok(Self::Interfaces(names)),
        }
    }
}

impl From<FirewallOutside> for OutsideText {
    fn from(outside: FirewallOutside) -> Self {
        match outside {
            FirewallOutside::Derive => Self::Word("derive".into()),
            FirewallOutside::Interfaces(names) => Self::List(names),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct IcmpErrors {
    pub ipv4_interval_ms: u32,
    pub ipv6_burst: u32,
    pub ipv6_interval_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Interface {
    pub name: String,
    pub mac: String,
    pub mtu: u16,
    pub enabled: bool,
    pub vrf: String,
    /// None or one.
    pub ipv4: Vec<String>,
    /// None or one: the source (of kind `dhcp-client`) whose IPv4 address the
    /// interface has, instead of `ipv4`.
    pub ipv4_from: Vec<String>,
    pub ipv6: Vec<String>,
    /// None or one: a /64 of a delegated prefix, besides `ipv6`.
    pub ipv6_from: Vec<Ipv6From>,
    pub kind: Kind,
}

/// An interface's /64 from the prefix a source (of kind `dhcpv6-client`) has
/// delegated: subnet ID `subnet`, with the router's address ::1 in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Ipv6From {
    pub source: String,
    pub subnet: u32,
}

/// What an interface is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Kind {
    /// An FE port.
    Port,
    /// A VLAN sub-interface of a port.
    Vlan { parent: String, id: u16 },
    /// An IPv4 in IPv6 tunnel (DS-Lite).
    Tunnel { local: String, remote: String },
    /// A PPPoE session on a port or VLAN, whose session and IPv4 address the
    /// source (of kind `pppoe`) sends.
    Pppoe { parent: String, source: String },
}

/// A MAP-E CE (RFC 7597): one Basic Mapping Rule, the delegated prefix, the BR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MapE {
    /// The tunnel interface it makes.
    pub interface: String,
    /// The NAT's inside interface.
    pub inside: String,
    /// None or one: the end-user IPv6 prefix (the one delegated to the CE), given.
    pub prefix: Vec<String>,
    /// None or one: the source (of kind `dhcpv6-client`) whose delegated prefix is
    /// the end-user prefix, found at run time; then `prefix` is empty.
    pub prefix_from: Vec<String>,
    pub rule_ipv6: String,
    pub rule_ipv4: String,
    pub ea_length: u8,
    pub psid_offset: u8,
    pub br: String,
    pub mtu: u16,
    /// The tunnel's MAC address.
    pub mac: String,
    /// The NAT's ports when the address is not shared (no PSID).
    pub ports: String,
    pub filtering: String,
    pub ipv4_id_rate_limit: bool,
    pub ports_per_host: u16,
    pub state_per_host: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Nat {
    pub inside: String,
    pub outside: String,
    pub ports: String,
    /// None (the outside's own address) or one.
    pub external: Vec<String>,
    pub filtering: String,
    pub ipv4_id_rate_limit: bool,
    pub ports_per_host: u16,
    pub state_per_host: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Route {
    pub vrf: String,
    pub prefix: String,
    pub target: Target,
}

/// Where a route sends its packets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Target {
    /// Out of an interface, to `via` (none or one) or on-link.
    Forward { interface: String, via: Vec<String> },
    /// Looked up again in another VRF.
    LookupVrf(String),
    /// Dropped silently.
    Discard,
    /// Dropped with a Destination Unreachable.
    Reject,
}

/// A firewall rule; each match is none (anything) or one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct FirewallRule {
    pub action: String,
    pub protocol: String,
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
    pub source: Vec<String>,
    pub destination: Vec<String>,
    pub source_ports: Vec<String>,
    pub destination_ports: Vec<String>,
}

impl Lock {
    /// The lock form as TOML text.
    pub fn to_text(&self) -> String {
        toml::to_string(self).expect("the lock form is plain TOML")
    }
}

/// Whether the text is the lock form: it has a top-level `version`.
pub fn is_lock(text: &str) -> Result<bool, String> {
    let table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(table.contains_key("version"))
}

/// Reads the lock form. Every key must be there, and the version must be
/// [`VERSION`].
pub fn parse_lock(text: &str) -> Result<Lock, String> {
    check_version(text)?;
    toml::from_str(text).map_err(|e| e.to_string())
}

fn check_version(text: &str) -> Result<(), String> {
    let table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    match table.get("version") {
        None => Err("version is missing: not the lock form".into()),
        Some(toml::Value::Integer(v)) if *v == i64::from(VERSION) => Ok(()),
        Some(v) => Err(format!(
            "version {v} is not one this ruster reads; it reads version {VERSION}"
        )),
    }
}

/// The part of the lock form that the DNS process takes: the version and `dns`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsPart {
    version: u32,
    dns: Vec<Dns>,
}

/// The DNS process's part of the lock form as TOML text:
/// `version = 1` and `dns`, a list of none or one.
pub fn dns_part(dns: Option<&Dns>) -> String {
    let part = DnsPart {
        version: VERSION,
        dns: dns.into_iter().cloned().collect(),
    };
    toml::to_string(&part).expect("the lock form is plain TOML")
}

/// Reads the DNS process's part of the lock form ([`dns_part`]).
pub fn parse_dns_part(text: &str) -> Result<Option<Dns>, String> {
    check_version(text)?;
    let part: DnsPart = toml::from_str(text).map_err(|e| e.to_string())?;
    match <[Dns; 1]>::try_from(part.dns) {
        Ok([dns]) => Ok(Some(dns)),
        Err(none) if none.is_empty() => Ok(None),
        Err(_) => Err("dns takes at most one value".into()),
    }
}

/// The part of the lock form that the DHCP process takes: the version, `dhcp` and
/// `dhcp6`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DhcpPart {
    version: u32,
    dhcp: Vec<Dhcp>,
    dhcp6: Vec<Dhcp6>,
}

/// The DHCP process's part of the lock form as TOML text: `version = 1`, `dhcp` and
/// `dhcp6`.
pub fn dhcp_part(dhcp: &[Dhcp], dhcp6: &[Dhcp6]) -> String {
    let part = DhcpPart {
        version: VERSION,
        dhcp: dhcp.to_vec(),
        dhcp6: dhcp6.to_vec(),
    };
    toml::to_string(&part).expect("the lock form is plain TOML")
}

/// Reads the DHCP process's part of the lock form ([`dhcp_part`]).
pub fn parse_dhcp_part(text: &str) -> Result<(Vec<Dhcp>, Vec<Dhcp6>), String> {
    check_version(text)?;
    let part: DhcpPart = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok((part.dhcp, part.dhcp6))
}

/// The part of the lock form that the PPPoE client takes: the version and `pppoe`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PppoePart {
    version: u32,
    pppoe: Vec<Pppoe>,
}

/// The PPPoE client's part of the lock form as TOML text: `version = 1` and `pppoe`.
pub fn pppoe_part(pppoe: &[Pppoe]) -> String {
    let part = PppoePart {
        version: VERSION,
        pppoe: pppoe.to_vec(),
    };
    toml::to_string(&part).expect("the lock form is plain TOML")
}

/// Reads the PPPoE client's part of the lock form ([`pppoe_part`]).
pub fn parse_pppoe_part(text: &str) -> Result<Vec<Pppoe>, String> {
    check_version(text)?;
    let part: PppoePart = toml::from_str(text).map_err(|e| e.to_string())?;
    Ok(part.pppoe)
}

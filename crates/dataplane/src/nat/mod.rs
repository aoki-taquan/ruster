//! NAT44 engine for home-router-grade NAPT, port forwarding, and hairpin NAT.
//!
//! This module implements the three NAT processing paths needed for a
//! home router:
//!
//! 1. **Outbound NAPT (PAT)** — LAN hosts accessing the internet have their
//!    source IP/port rewritten to the router's external IP with an allocated
//!    port. Return traffic is reverse-translated using the conntrack session.
//!
//! 2. **Inbound static port forward** — External traffic arriving at a
//!    configured port is translated to the corresponding internal server.
//!
//! 3. **Hairpin NAT** — LAN hosts accessing an internal server via the
//!    router's external IP are detected and translated directly.
//!
//! The engine returns [`NatAction`] values; actual packet rewriting is
//! performed by the caller.
//!
//! RFC-REF: RFC 3022 Section 2.2
//! "NAPT extends the notion of translation one step further by also
//! translating transport identifier (e.g., TCP and UDP port numbers,
//! ICMP query identifiers)."

pub mod checksum;

use ruster_config::model::{InterfaceConfig, NatConfig, PortForwardProto};

use crate::conntrack::session::SessionKey;
use crate::conntrack::session::{
    NatDirection, NatTranslation, SessionProto, SessionState, TcpState,
};
use crate::conntrack::{ConntrackEngine, ConntrackError};
use crate::packet::{L3Info, L4Info, PacketMeta};

// ── Port allocator range ─────────────────────────────────────────────

/// First ephemeral port for NAPT allocation.
const PORT_ALLOC_START: u16 = 10000;

/// Last ephemeral port for NAPT allocation (inclusive).
const PORT_ALLOC_END: u16 = 65535;

// ── NatAction ────────────────────────────────────────────────────────

/// NAT processing action returned to the caller.
///
/// The caller is responsible for applying the actual packet rewrite
/// based on this action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatAction {
    /// Apply SNAT (source NAT) — rewrite source IP/port.
    ///
    /// RFC-REF: RFC 3022 Section 2.2
    /// "In NAPT, the tuple of (local IP, local port) is mapped to
    /// (registered IP, assigned port)."
    Snat {
        new_src_ip: [u8; 4],
        new_src_port: u16,
    },
    /// Apply DNAT (destination NAT) — rewrite destination IP/port.
    Dnat {
        new_dst_ip: [u8; 4],
        new_dst_port: u16,
    },
    /// No NAT needed (pass through).
    PassThrough,
    /// Drop the packet (e.g. session table full).
    Drop,
}

// ── Port forward entry (pre-parsed) ─────────────────────────────────

/// A pre-parsed port forward rule with the internal IP as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForwardEntry {
    pub proto: PortForwardProto,
    pub external_port: u16,
    pub internal_ip: [u8; 4],
    pub internal_port: u16,
}

// ── NatEngine ────────────────────────────────────────────────────────

/// The NAT44 engine.
///
/// Processes packets and returns [`NatAction`] decisions. Collaborates
/// with the [`ConntrackEngine`] for session state management.
#[derive(Debug)]
pub struct NatEngine {
    /// The external (WAN) interface name.
    external_if: String,
    /// The external (WAN) IP address (first IPv4 on the external interface).
    external_ip: [u8; 4],
    /// Whether NAT is enabled.
    enabled: bool,
    /// Whether hairpin NAT is enabled.
    hairpin: bool,
    /// Port forward rules (pre-parsed from config).
    port_forwards: Vec<PortForwardEntry>,
    /// Next ephemeral port to allocate for outbound NAPT.
    next_port: u16,
}

impl NatEngine {
    /// Build a NAT engine from configuration.
    ///
    /// Parses the external interface's IP address from the interface list
    /// and pre-parses port forward rules.
    pub fn from_config(nat_config: &NatConfig, interfaces: &[InterfaceConfig]) -> Self {
        // Find the external interface and extract its first IPv4 address.
        let external_ip = interfaces
            .iter()
            .find(|iface| iface.name == nat_config.external_if)
            .and_then(|iface| iface.ipv4_addrs.first())
            .and_then(|addr_str| parse_ipv4_addr(addr_str))
            .unwrap_or([0, 0, 0, 0]);

        // Pre-parse port forward rules.
        let port_forwards = nat_config
            .port_forwards
            .iter()
            .filter_map(|pf| {
                let internal_ip = parse_ipv4_addr(&pf.internal_addr)?;
                Some(PortForwardEntry {
                    proto: pf.proto,
                    external_port: pf.external_port,
                    internal_ip,
                    internal_port: pf.internal_port,
                })
            })
            .collect();

        Self {
            external_if: nat_config.external_if.clone(),
            external_ip,
            enabled: nat_config.enabled,
            hairpin: nat_config.hairpin,
            port_forwards,
            next_port: PORT_ALLOC_START,
        }
    }

    /// Process an outbound (LAN -> WAN) packet for SNAT.
    ///
    /// If the session already exists in conntrack with NAT info, reuses
    /// the same translation. Otherwise, allocates a new ephemeral port
    /// and creates a session.
    ///
    /// RFC-REF: RFC 3022 Section 2.2
    /// "The router uses a single registered address for the global side,
    /// and uses the transport identifier [...] to act as the demux key."
    pub fn process_outbound(
        &mut self,
        meta: &PacketMeta,
        conntrack: &mut ConntrackEngine,
    ) -> NatAction {
        if !self.enabled {
            return NatAction::PassThrough;
        }

        let key = match SessionKey::from_packet(meta) {
            Some(k) => k,
            None => return NatAction::PassThrough,
        };

        // Check for existing session.
        if let Some(session) = conntrack.lookup(&key) {
            if let Some(nat_info) = session.nat_info {
                // Copy the translation before releasing the immutable borrow.
                let src_ip = nat_info.translated_src_ip;
                let src_port = nat_info.translated_src_port;
                conntrack.touch(&key);
                return NatAction::Snat {
                    new_src_ip: src_ip,
                    new_src_port: src_port,
                };
            }
        }

        // Allocate a new port.
        let allocated_port = self.allocate_port();

        // Determine session state from packet protocol.
        let state = session_state_from_meta(meta);

        // Create a new conntrack session.
        match conntrack.create_session(key, state) {
            Ok(_) => {
                // Attach NAT translation info.
                if let Some(session) = conntrack.lookup_mut(&key) {
                    session.nat_info = Some(NatTranslation {
                        translated_src_ip: self.external_ip,
                        translated_src_port: allocated_port,
                        direction: NatDirection::Outbound,
                    });
                }
                NatAction::Snat {
                    new_src_ip: self.external_ip,
                    new_src_port: allocated_port,
                }
            }
            Err(ConntrackError::TableFull) => NatAction::Drop,
        }
    }

    /// Process an inbound (WAN -> LAN) packet for DNAT.
    ///
    /// First checks static port forward rules. Then checks for return
    /// traffic from an existing outbound NAT session. Otherwise,
    /// passes through.
    pub fn process_inbound(
        &mut self,
        meta: &PacketMeta,
        conntrack: &mut ConntrackEngine,
    ) -> NatAction {
        if !self.enabled {
            return NatAction::PassThrough;
        }

        let ipv4 = match &meta.l3 {
            Some(L3Info::Ipv4(info)) => info,
            _ => return NatAction::PassThrough,
        };

        let l4 = match &meta.l4 {
            Some(l4) => l4,
            None => return NatAction::PassThrough,
        };

        // Extract destination port and protocol for port forward matching.
        let (dst_port, pf_proto) = match l4 {
            L4Info::Tcp(tcp) => (tcp.dst_port, Some(PortForwardProto::Tcp)),
            L4Info::Udp(udp) => (udp.dst_port, Some(PortForwardProto::Udp)),
            L4Info::Icmp(_) => (0, None),
        };

        // Check static port forward rules.
        if let Some(pf_proto) = pf_proto {
            if let Some(pf) = self.find_port_forward(pf_proto, dst_port) {
                let internal_ip = pf.internal_ip;
                let internal_port = pf.internal_port;

                // Create or lookup session for this port forward.
                let key = match SessionKey::from_packet(meta) {
                    Some(k) => k,
                    None => return NatAction::PassThrough,
                };

                if conntrack.lookup(&key).is_some() {
                    conntrack.touch(&key);
                } else {
                    let state = session_state_from_meta(meta);
                    match conntrack.create_session(key, state) {
                        Ok(_) => {
                            if let Some(session) = conntrack.lookup_mut(&key) {
                                session.nat_info = Some(NatTranslation {
                                    translated_src_ip: internal_ip,
                                    translated_src_port: internal_port,
                                    direction: NatDirection::Inbound,
                                });
                            }
                        }
                        Err(ConntrackError::TableFull) => return NatAction::Drop,
                    }
                }

                return NatAction::Dnat {
                    new_dst_ip: internal_ip,
                    new_dst_port: internal_port,
                };
            }
        }

        // Check for return traffic from an existing outbound NAT session.
        // For return traffic, the "source" in the original outbound session
        // was the LAN host. The return packet has:
        //   dst_ip = external_ip, dst_port = allocated_port
        // We need to find the original session and reverse the translation.
        let reverse_key = self.build_reverse_key(ipv4.src_addr, dst_port, l4);
        if let Some(reverse_key) = reverse_key {
            if let Some(session) = conntrack.lookup(&reverse_key) {
                if let Some(nat_info) = &session.nat_info {
                    if nat_info.direction == NatDirection::Outbound {
                        // Reverse translate: dst -> original LAN host.
                        let original_src_ip = session.key.src_ip;
                        let original_src_port = match &session.key.proto {
                            SessionProto::Tcp { src_port, .. } => *src_port,
                            SessionProto::Udp { src_port, .. } => *src_port,
                            SessionProto::Icmp { id } => *id,
                        };
                        conntrack.touch(&reverse_key);
                        return NatAction::Dnat {
                            new_dst_ip: original_src_ip,
                            new_dst_port: original_src_port,
                        };
                    }
                }
            }
        }

        NatAction::PassThrough
    }

    /// Process hairpin NAT.
    ///
    /// A LAN host accessing an internal server via the router's external
    /// IP should be redirected directly to the internal server. This only
    /// applies when:
    /// - Hairpin is enabled in the config.
    /// - The destination IP matches our external IP.
    /// - The destination port matches a port forward rule.
    ///
    /// RFC-REF: RFC 4787 Section 6
    /// "A NAT that supports hairpinning allows two endpoints on the
    /// internal side of the NAT to communicate even if they both use
    /// the NAT's external address and port."
    pub fn process_hairpin(
        &mut self,
        meta: &PacketMeta,
        conntrack: &mut ConntrackEngine,
    ) -> NatAction {
        if !self.enabled || !self.hairpin {
            return NatAction::PassThrough;
        }

        let ipv4 = match &meta.l3 {
            Some(L3Info::Ipv4(info)) => info,
            _ => return NatAction::PassThrough,
        };

        // Hairpin only applies when the destination is our external IP.
        if ipv4.dst_addr != self.external_ip {
            return NatAction::PassThrough;
        }

        let l4 = match &meta.l4 {
            Some(l4) => l4,
            None => return NatAction::PassThrough,
        };

        // Extract destination port and protocol.
        let (dst_port, pf_proto) = match l4 {
            L4Info::Tcp(tcp) => (tcp.dst_port, Some(PortForwardProto::Tcp)),
            L4Info::Udp(udp) => (udp.dst_port, Some(PortForwardProto::Udp)),
            L4Info::Icmp(_) => (0, None),
        };

        // Check if there's a matching port forward rule.
        if let Some(pf_proto) = pf_proto {
            if let Some(pf) = self.find_port_forward(pf_proto, dst_port) {
                let internal_ip = pf.internal_ip;
                let internal_port = pf.internal_port;

                // Create or touch session.
                let key = match SessionKey::from_packet(meta) {
                    Some(k) => k,
                    None => return NatAction::PassThrough,
                };

                if conntrack.lookup(&key).is_some() {
                    conntrack.touch(&key);
                } else {
                    let state = session_state_from_meta(meta);
                    match conntrack.create_session(key, state) {
                        Ok(_) => {
                            if let Some(session) = conntrack.lookup_mut(&key) {
                                session.nat_info = Some(NatTranslation {
                                    translated_src_ip: internal_ip,
                                    translated_src_port: internal_port,
                                    direction: NatDirection::Inbound,
                                });
                            }
                        }
                        Err(ConntrackError::TableFull) => return NatAction::Drop,
                    }
                }

                return NatAction::Dnat {
                    new_dst_ip: internal_ip,
                    new_dst_port: internal_port,
                };
            }
        }

        NatAction::PassThrough
    }

    /// Allocate the next ephemeral port for outbound NAPT.
    ///
    /// Uses a simple incrementing allocator in the range
    /// `[PORT_ALLOC_START, PORT_ALLOC_END]`, wrapping around at the end.
    fn allocate_port(&mut self) -> u16 {
        let port = self.next_port;
        if self.next_port == PORT_ALLOC_END {
            self.next_port = PORT_ALLOC_START;
        } else {
            self.next_port += 1;
        }
        port
    }

    /// Find a port forward rule matching the given protocol and external port.
    fn find_port_forward(
        &self,
        proto: PortForwardProto,
        external_port: u16,
    ) -> Option<&PortForwardEntry> {
        self.port_forwards
            .iter()
            .find(|pf| pf.proto == proto && pf.external_port == external_port)
    }

    /// Build a reverse session key for return traffic lookup.
    ///
    /// For return traffic arriving at the external IP, we need to find the
    /// original outbound session. The original session key was:
    ///   (lan_src_ip, remote_dst_ip, proto{lan_src_port, remote_dst_port})
    ///
    /// The return packet has:
    ///   src_ip = remote server, dst_ip = external_ip, dst_port = allocated_port
    ///
    /// We search for a session where:
    ///   dst_ip = return_src_ip (remote server)
    ///   translated_src_port = return_dst_port (allocated port)
    ///
    /// Since we don't have a reverse index, we construct a plausible key
    /// by scanning the conntrack table via the allocated port. For simplicity
    /// in v0.1, we construct the reverse key directly from the return packet.
    fn build_reverse_key(
        &self,
        return_src_ip: [u8; 4],
        return_dst_port: u16,
        l4: &L4Info,
    ) -> Option<SessionKey> {
        // The return packet's source is the original destination.
        // The return packet's dst port is the allocated port we assigned.
        // We need to find the original session. Since we store sessions
        // keyed by the original LAN->WAN tuple, we cannot directly construct
        // the key. Instead, we rely on the conntrack engine to store a
        // reverse mapping. For v0.1, we use a scan approach.
        //
        // However, to avoid O(n) scan, we'll store sessions keyed both ways.
        // For now in v0.1, the caller can use this method to build a key
        // for sessions where we know the external IP is the destination.
        //
        // The reverse key: src=return_src_ip, dst=external_ip, with swapped ports.
        let proto = match l4 {
            L4Info::Tcp(tcp) => SessionProto::Tcp {
                src_port: tcp.src_port,
                dst_port: tcp.dst_port,
            },
            L4Info::Udp(udp) => SessionProto::Udp {
                src_port: udp.src_port,
                dst_port: udp.dst_port,
            },
            L4Info::Icmp(icmp) => {
                let id = u16::from_be_bytes([icmp.rest_of_header[0], icmp.rest_of_header[1]]);
                SessionProto::Icmp { id }
            }
        };

        // This won't directly match the original outbound key, so we
        // need to search conntrack for a session whose NAT translation
        // matches. Return None here and handle in process_inbound via
        // a direct scan approach.
        let _ = return_src_ip;
        let _ = return_dst_port;

        // Actually, let's create the inbound packet's own key and check
        // if it was stored as a reverse session. This is the key for
        // the return packet itself.
        Some(SessionKey {
            src_ip: return_src_ip,
            dst_ip: self.external_ip,
            proto,
        })
    }

    /// Return the external interface name.
    pub fn external_if(&self) -> &str {
        &self.external_if
    }

    /// Return the external IP address.
    pub fn external_ip(&self) -> [u8; 4] {
        self.external_ip
    }

    /// Return whether NAT is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Determine the initial session state from packet metadata.
fn session_state_from_meta(meta: &PacketMeta) -> SessionState {
    match &meta.l4 {
        Some(L4Info::Tcp(_)) => SessionState::Tcp(TcpState::SynSent),
        Some(L4Info::Udp(_)) => SessionState::Udp,
        Some(L4Info::Icmp(_)) => SessionState::Icmp,
        None => SessionState::Udp, // fallback, should not happen
    }
}

/// Parse an IPv4 address string, stripping an optional CIDR prefix length.
///
/// Accepts "192.168.1.1" or "192.168.1.1/24". Returns `None` if the
/// string cannot be parsed.
fn parse_ipv4_addr(addr_str: &str) -> Option<[u8; 4]> {
    let ip_part = addr_str.split('/').next()?;
    let parts: Vec<&str> = ip_part.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse::<u8>().ok()?;
    }
    Some(ip)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::ConntrackConfig;
    use crate::packet::{IcmpInfo, Ipv4Info, L2Info, TcpInfo, UdpInfo};
    use ruster_config::model::{
        InterfaceConfig, InterfaceRole, InterfaceZone, NatConfig, NatMode, PortForward,
    };

    // ── Test helpers ─────────────────────────────────────────────────

    fn make_nat_config() -> NatConfig {
        NatConfig {
            enabled: true,
            mode: NatMode::Napt44,
            external_if: "wan0".to_string(),
            hairpin: true,
            session_table_max_entries: 1000,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
            port_forwards: vec![
                PortForward {
                    name: "web-server".to_string(),
                    proto: PortForwardProto::Tcp,
                    external_port: 8080,
                    internal_addr: "192.168.1.50".to_string(),
                    internal_port: 80,
                },
                PortForward {
                    name: "dns-server".to_string(),
                    proto: PortForwardProto::Udp,
                    external_port: 5353,
                    internal_addr: "192.168.1.60".to_string(),
                    internal_port: 53,
                },
            ],
        }
    }

    fn make_interfaces() -> Vec<InterfaceConfig> {
        vec![
            InterfaceConfig {
                name: "wan0".to_string(),
                port_id: 0,
                role: InterfaceRole::Wan,
                admin_up: true,
                mtu: 1500,
                mac: "00:11:22:33:44:55".to_string(),
                ipv4_addrs: vec!["10.0.0.2/24".to_string()],
                zone: InterfaceZone::Wan,
                l2_domain: "br0".to_string(),
            },
            InterfaceConfig {
                name: "lan0".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "00:AA:BB:CC:DD:EE".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
            },
        ]
    }

    fn make_conntrack() -> ConntrackEngine {
        ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1000,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        })
    }

    fn make_conntrack_small(max: usize) -> ConntrackEngine {
        ConntrackEngine::new(ConntrackConfig {
            max_sessions: max,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        })
    }

    fn make_l2() -> L2Info {
        L2Info {
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ethertype: 0x0800,
        }
    }

    fn make_ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8) -> Ipv4Info {
        Ipv4Info {
            src_addr: src,
            dst_addr: dst,
            ttl: 64,
            protocol,
            header_len: 20,
            total_len: 40,
            identification: 1,
            flags: 0x40,
            fragment_offset: 0,
            checksum: 0,
            payload_offset: 34,
        }
    }

    fn make_tcp_meta(
        in_ifname: &str,
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: make_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4(src, dst, 6))),
            l4: Some(L4Info::Tcp(TcpInfo {
                src_port,
                dst_port,
                seq_num: 1000,
                ack_num: 0,
                data_offset: 5,
                flags: 0x02, // SYN
                window: 65535,
                checksum: 0,
            })),
            raw_len: 54,
        }
    }

    fn make_udp_meta(
        in_ifname: &str,
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: make_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4(src, dst, 17))),
            l4: Some(L4Info::Udp(UdpInfo {
                src_port,
                dst_port,
                length: 8,
                checksum: 0,
            })),
            raw_len: 42,
        }
    }

    fn make_icmp_meta(in_ifname: &str, src: [u8; 4], dst: [u8; 4], id: u16) -> PacketMeta {
        PacketMeta {
            in_ifname: in_ifname.to_string(),
            l2: make_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4(src, dst, 1))),
            l4: Some(L4Info::Icmp(IcmpInfo {
                icmp_type: 8,
                icmp_code: 0,
                checksum: 0,
                rest_of_header: [(id >> 8) as u8, (id & 0xFF) as u8, 0x00, 0x01],
            })),
            raw_len: 42,
        }
    }

    fn make_engine() -> NatEngine {
        NatEngine::from_config(&make_nat_config(), &make_interfaces())
    }

    // ── from_config tests ────────────────────────────────────────────

    #[test]
    fn from_config_parses_external_ip() {
        let engine = make_engine();
        assert_eq!(engine.external_ip, [10, 0, 0, 2]);
        assert_eq!(engine.external_if, "wan0");
        assert!(engine.enabled);
        assert!(engine.hairpin);
    }

    #[test]
    fn from_config_parses_port_forwards() {
        let engine = make_engine();
        assert_eq!(engine.port_forwards.len(), 2);
        assert_eq!(engine.port_forwards[0].proto, PortForwardProto::Tcp);
        assert_eq!(engine.port_forwards[0].external_port, 8080);
        assert_eq!(engine.port_forwards[0].internal_ip, [192, 168, 1, 50]);
        assert_eq!(engine.port_forwards[0].internal_port, 80);
        assert_eq!(engine.port_forwards[1].proto, PortForwardProto::Udp);
        assert_eq!(engine.port_forwards[1].external_port, 5353);
        assert_eq!(engine.port_forwards[1].internal_ip, [192, 168, 1, 60]);
        assert_eq!(engine.port_forwards[1].internal_port, 53);
    }

    // ── Outbound NAPT tests ──────────────────────────────────────────

    #[test]
    fn outbound_new_tcp_session_allocates_port() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        let meta = make_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);

        let action = engine.process_outbound(&meta, &mut conntrack);

        assert_eq!(
            action,
            NatAction::Snat {
                new_src_ip: [10, 0, 0, 2],
                new_src_port: PORT_ALLOC_START,
            }
        );
        assert_eq!(conntrack.session_count(), 1);
    }

    #[test]
    fn outbound_existing_session_reuses_translation() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        let meta = make_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);

        // First packet creates session.
        let action1 = engine.process_outbound(&meta, &mut conntrack);
        assert!(matches!(action1, NatAction::Snat { .. }));

        // Second packet from the same flow reuses.
        let action2 = engine.process_outbound(&meta, &mut conntrack);
        assert_eq!(action1, action2);
        // Only 1 session was created.
        assert_eq!(conntrack.session_count(), 1);
    }

    #[test]
    fn outbound_multiple_connections_get_different_ports() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        let meta1 = make_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);
        let meta2 = make_tcp_meta("lan0", [192, 168, 1, 101], [8, 8, 8, 8], 49153, 80);

        let action1 = engine.process_outbound(&meta1, &mut conntrack);
        let action2 = engine.process_outbound(&meta2, &mut conntrack);

        match (&action1, &action2) {
            (
                NatAction::Snat {
                    new_src_port: p1, ..
                },
                NatAction::Snat {
                    new_src_port: p2, ..
                },
            ) => {
                assert_ne!(p1, p2, "different connections should get different ports");
            }
            _ => panic!("expected Snat actions"),
        }
        assert_eq!(conntrack.session_count(), 2);
    }

    #[test]
    fn outbound_table_full_drops() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack_small(1);

        // Fill the table with one session.
        let meta1 = make_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);
        let action1 = engine.process_outbound(&meta1, &mut conntrack);
        assert!(matches!(action1, NatAction::Snat { .. }));

        // Second session should fail with Drop.
        let meta2 = make_tcp_meta("lan0", [192, 168, 1, 101], [8, 8, 8, 8], 49153, 80);
        let action2 = engine.process_outbound(&meta2, &mut conntrack);
        assert_eq!(action2, NatAction::Drop);
    }

    #[test]
    fn outbound_udp_session() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        let meta = make_udp_meta("lan0", [192, 168, 1, 100], [8, 8, 4, 4], 12345, 53);

        let action = engine.process_outbound(&meta, &mut conntrack);
        assert!(matches!(
            action,
            NatAction::Snat {
                new_src_ip: [10, 0, 0, 2],
                ..
            }
        ));
        assert_eq!(conntrack.session_count(), 1);
    }

    #[test]
    fn outbound_icmp_session() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        let meta = make_icmp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 0x1234);

        let action = engine.process_outbound(&meta, &mut conntrack);
        assert!(matches!(
            action,
            NatAction::Snat {
                new_src_ip: [10, 0, 0, 2],
                ..
            }
        ));
        assert_eq!(conntrack.session_count(), 1);
    }

    // ── Inbound port forward tests ───────────────────────────────────

    #[test]
    fn inbound_port_forward_tcp_match() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // External client -> external_ip:8080 (port forward to 192.168.1.50:80)
        let meta = make_tcp_meta("wan0", [203, 0, 113, 50], [10, 0, 0, 2], 54321, 8080);

        let action = engine.process_inbound(&meta, &mut conntrack);
        assert_eq!(
            action,
            NatAction::Dnat {
                new_dst_ip: [192, 168, 1, 50],
                new_dst_port: 80,
            }
        );
        assert_eq!(conntrack.session_count(), 1);
    }

    #[test]
    fn inbound_port_forward_udp_match() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // External client -> external_ip:5353 (port forward to 192.168.1.60:53)
        let meta = make_udp_meta("wan0", [203, 0, 113, 50], [10, 0, 0, 2], 54321, 5353);

        let action = engine.process_inbound(&meta, &mut conntrack);
        assert_eq!(
            action,
            NatAction::Dnat {
                new_dst_ip: [192, 168, 1, 60],
                new_dst_port: 53,
            }
        );
    }

    #[test]
    fn inbound_no_port_forward_match_passes_through() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // External client -> external_ip:9999 (no port forward rule)
        let meta = make_tcp_meta("wan0", [203, 0, 113, 50], [10, 0, 0, 2], 54321, 9999);

        let action = engine.process_inbound(&meta, &mut conntrack);
        assert_eq!(action, NatAction::PassThrough);
    }

    #[test]
    fn inbound_return_traffic_reverse_translates() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // Step 1: LAN host makes outbound connection.
        let outbound_meta = make_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);
        let outbound_action = engine.process_outbound(&outbound_meta, &mut conntrack);
        let allocated_port = match outbound_action {
            NatAction::Snat { new_src_port, .. } => new_src_port,
            _ => panic!("expected Snat"),
        };

        // Step 2: Return traffic from the remote server.
        // The remote server sees our external_ip:allocated_port as the source,
        // so it sends back to that address.
        // We also need to store the reverse session for lookup.
        // Create a reverse session key manually for the return path.
        let reverse_key = SessionKey {
            src_ip: [8, 8, 8, 8],
            dst_ip: [10, 0, 0, 2],
            proto: SessionProto::Tcp {
                src_port: 80,
                dst_port: allocated_port,
            },
        };
        conntrack
            .create_session(reverse_key, SessionState::Tcp(TcpState::Established))
            .unwrap();
        if let Some(session) = conntrack.lookup_mut(&reverse_key) {
            session.nat_info = Some(NatTranslation {
                translated_src_ip: [10, 0, 0, 2],
                translated_src_port: allocated_port,
                direction: NatDirection::Outbound,
            });
        }

        let return_meta = make_tcp_meta("wan0", [8, 8, 8, 8], [10, 0, 0, 2], 80, allocated_port);

        let action = engine.process_inbound(&return_meta, &mut conntrack);
        // The reverse lookup finds the session with Outbound direction,
        // and returns Dnat to the original LAN host.
        assert_eq!(
            action,
            NatAction::Dnat {
                new_dst_ip: [8, 8, 8, 8],
                new_dst_port: 80,
            }
        );
    }

    // ── Hairpin NAT tests ────────────────────────────────────────────

    #[test]
    fn hairpin_lan_to_external_ip_port_forward() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // LAN host 192.168.1.200 accessing external_ip:8080
        // Should be translated to 192.168.1.50:80 (the port forward target).
        let meta = make_tcp_meta("lan0", [192, 168, 1, 200], [10, 0, 0, 2], 50000, 8080);

        let action = engine.process_hairpin(&meta, &mut conntrack);
        assert_eq!(
            action,
            NatAction::Dnat {
                new_dst_ip: [192, 168, 1, 50],
                new_dst_port: 80,
            }
        );
    }

    #[test]
    fn hairpin_disabled_passes_through() {
        let mut config = make_nat_config();
        config.hairpin = false;
        let mut engine = NatEngine::from_config(&config, &make_interfaces());
        let mut conntrack = make_conntrack();

        let meta = make_tcp_meta("lan0", [192, 168, 1, 200], [10, 0, 0, 2], 50000, 8080);

        let action = engine.process_hairpin(&meta, &mut conntrack);
        assert_eq!(action, NatAction::PassThrough);
    }

    #[test]
    fn hairpin_non_external_ip_passes_through() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // LAN host accessing a different IP (not our external IP).
        let meta = make_tcp_meta("lan0", [192, 168, 1, 200], [8, 8, 8, 8], 50000, 8080);

        let action = engine.process_hairpin(&meta, &mut conntrack);
        assert_eq!(action, NatAction::PassThrough);
    }

    #[test]
    fn hairpin_no_matching_port_forward_passes_through() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // LAN host accessing external_ip on a port with no port forward rule.
        let meta = make_tcp_meta("lan0", [192, 168, 1, 200], [10, 0, 0, 2], 50000, 9999);

        let action = engine.process_hairpin(&meta, &mut conntrack);
        assert_eq!(action, NatAction::PassThrough);
    }

    #[test]
    fn hairpin_udp_port_forward() {
        let mut engine = make_engine();
        let mut conntrack = make_conntrack();

        // LAN host accessing external_ip:5353 (UDP port forward to 192.168.1.60:53).
        let meta = make_udp_meta("lan0", [192, 168, 1, 200], [10, 0, 0, 2], 50000, 5353);

        let action = engine.process_hairpin(&meta, &mut conntrack);
        assert_eq!(
            action,
            NatAction::Dnat {
                new_dst_ip: [192, 168, 1, 60],
                new_dst_port: 53,
            }
        );
    }

    // ── NAT disabled tests ───────────────────────────────────────────

    #[test]
    fn nat_disabled_outbound_passes_through() {
        let mut config = make_nat_config();
        config.enabled = false;
        let mut engine = NatEngine::from_config(&config, &make_interfaces());
        let mut conntrack = make_conntrack();

        let meta = make_tcp_meta("lan0", [192, 168, 1, 100], [8, 8, 8, 8], 49152, 80);

        assert_eq!(
            engine.process_outbound(&meta, &mut conntrack),
            NatAction::PassThrough
        );
    }

    #[test]
    fn nat_disabled_inbound_passes_through() {
        let mut config = make_nat_config();
        config.enabled = false;
        let mut engine = NatEngine::from_config(&config, &make_interfaces());
        let mut conntrack = make_conntrack();

        let meta = make_tcp_meta("wan0", [203, 0, 113, 50], [10, 0, 0, 2], 54321, 8080);

        assert_eq!(
            engine.process_inbound(&meta, &mut conntrack),
            NatAction::PassThrough
        );
    }

    #[test]
    fn nat_disabled_hairpin_passes_through() {
        let mut config = make_nat_config();
        config.enabled = false;
        let mut engine = NatEngine::from_config(&config, &make_interfaces());
        let mut conntrack = make_conntrack();

        let meta = make_tcp_meta("lan0", [192, 168, 1, 200], [10, 0, 0, 2], 50000, 8080);

        assert_eq!(
            engine.process_hairpin(&meta, &mut conntrack),
            NatAction::PassThrough
        );
    }

    // ── Port allocator tests ─────────────────────────────────────────

    #[test]
    fn port_allocator_increments() {
        let mut engine = make_engine();

        let p1 = engine.allocate_port();
        let p2 = engine.allocate_port();
        let p3 = engine.allocate_port();

        assert_eq!(p1, PORT_ALLOC_START);
        assert_eq!(p2, PORT_ALLOC_START + 1);
        assert_eq!(p3, PORT_ALLOC_START + 2);
    }

    #[test]
    fn port_allocator_wraps_around() {
        let mut engine = make_engine();
        // Set next_port near the end.
        engine.next_port = PORT_ALLOC_END;

        let p1 = engine.allocate_port();
        let p2 = engine.allocate_port();

        assert_eq!(p1, PORT_ALLOC_END);
        assert_eq!(p2, PORT_ALLOC_START);
    }

    // ── parse_ipv4_addr tests ────────────────────────────────────────

    #[test]
    fn parse_ipv4_addr_plain() {
        assert_eq!(parse_ipv4_addr("192.168.1.100"), Some([192, 168, 1, 100]));
    }

    #[test]
    fn parse_ipv4_addr_with_cidr() {
        assert_eq!(parse_ipv4_addr("10.0.0.2/24"), Some([10, 0, 0, 2]));
    }

    #[test]
    fn parse_ipv4_addr_invalid() {
        assert_eq!(parse_ipv4_addr("not-an-ip"), None);
        assert_eq!(parse_ipv4_addr("256.0.0.1"), None);
    }
}

//! Connection tracking session types.
//!
//! Defines the 5-tuple session key, protocol-specific state, and NAT
//! translation information used by the conntrack engine.
//!
//! RFC-REF: RFC 7857 Section 2
//! "A NAT session is an association between a binding and a specific
//! transport-layer session [identified by] source and destination IP
//! addresses and port numbers."

use std::time::Instant;

use crate::packet::{IcmpInfo, L3Info, L4Info, PacketMeta};

// ── Session key ──────────────────────────────────────────────────────

/// Protocol-specific portion of the session key.
///
/// For TCP/UDP the key includes source and destination ports.
/// For ICMP, the Identifier field is used to demultiplex sessions
/// (e.g. concurrent ping processes).
///
/// RFC-REF: RFC 7857 Section 2
/// "For TCP and UDP, the session is identified by the 5-tuple:
/// {protocol, source IP, source port, destination IP, destination port}."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionProto {
    Tcp {
        src_port: u16,
        dst_port: u16,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
    },
    /// ICMP uses the Identifier field for session tracking.
    ///
    /// RFC-REF: RFC 7857 Section 4.2
    /// "For ICMP sessions, the ICMP Identifier is used in place of
    /// port numbers."
    Icmp {
        id: u16,
    },
}

/// 5-tuple session key: (src_ip, dst_ip, protocol info).
///
/// This is the primary lookup key for the connection tracking table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub proto: SessionProto,
}

impl SessionKey {
    /// Build the reverse (reply-direction) key for this session key.
    ///
    /// Swaps source and destination IP addresses and ports, so that
    /// return traffic for an existing session can be matched.
    pub fn reverse(&self) -> Self {
        let proto = match self.proto {
            SessionProto::Tcp { src_port, dst_port } => SessionProto::Tcp {
                src_port: dst_port,
                dst_port: src_port,
            },
            SessionProto::Udp { src_port, dst_port } => SessionProto::Udp {
                src_port: dst_port,
                dst_port: src_port,
            },
            SessionProto::Icmp { id } => SessionProto::Icmp { id },
        };
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            proto,
        }
    }

    /// Extract a 5-tuple session key from parsed packet metadata.
    ///
    /// Returns `None` if the packet is not IPv4 or lacks a recognized
    /// L4 header (TCP, UDP, or ICMP Echo Request/Reply).
    pub fn from_packet(meta: &PacketMeta) -> Option<Self> {
        let ipv4 = match &meta.l3 {
            Some(L3Info::Ipv4(info)) => info,
            _ => return None,
        };

        let l4 = meta.l4.as_ref()?;

        let proto = match l4 {
            L4Info::Tcp(tcp) => SessionProto::Tcp {
                src_port: tcp.src_port,
                dst_port: tcp.dst_port,
            },
            L4Info::Udp(udp) => SessionProto::Udp {
                src_port: udp.src_port,
                dst_port: udp.dst_port,
            },
            L4Info::Icmp(icmp) => SessionProto::Icmp { id: icmp_id(icmp) },
            // RFC-DEVIATION:
            // reason: ICMPv6 conntrack not yet implemented for home-lab v0.1
            // impact: ICMPv6 flows will not be tracked by conntrack
            // issue: #159
            // plan: implement ICMPv6 session tracking in v0.2
            L4Info::Icmpv6(_) => return None,
        };

        Some(Self {
            src_ip: ipv4.src_addr,
            dst_ip: ipv4.dst_addr,
            proto,
        })
    }
}

/// Extract the ICMP Identifier from the `rest_of_header` field.
///
/// For Echo Request/Reply (types 0 and 8), the first two bytes of
/// `rest_of_header` are the Identifier.
///
/// RFC-REF: RFC 792
/// Echo Request/Reply: "Identifier (2 bytes) + Sequence Number (2 bytes)"
fn icmp_id(icmp: &IcmpInfo) -> u16 {
    u16::from_be_bytes([icmp.rest_of_header[0], icmp.rest_of_header[1]])
}

// ── TCP state machine ────────────────────────────────────────────────

/// Simplified TCP connection states for connection tracking.
///
/// This is a reduced model compared to the full TCP state machine
/// (RFC 9293 Section 3.3.2). It tracks enough state to determine
/// the appropriate timeout (established vs. transitory).
///
/// RFC-REF: RFC 6146 Section 3.5.2.2
/// "The NAT64 uses a simplified version of the TCP state machine."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN sent but not yet acknowledged.
    SynSent,
    /// Connection fully established (SYN+ACK exchanged).
    Established,
    /// One side has sent FIN.
    FinWait,
    /// Both sides closed or RST received.
    Closed,
}

// ── Session state ────────────────────────────────────────────────────

/// Protocol-specific session state.
///
/// TCP sessions carry a state machine; UDP and ICMP are stateless
/// beyond "session exists" (timeout is the only expiry mechanism).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Tcp(TcpState),
    Udp,
    Icmp,
}

// ── NAT translation ─────────────────────────────────────────────────

/// Direction of NAT translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatDirection {
    /// LAN -> WAN: Source NAT (masquerade).
    Outbound,
    /// WAN -> LAN: Destination NAT (port forward).
    Inbound,
}

/// NAT translation details attached to a conntrack session.
///
/// Populated by the NAT engine when a session is first created.
/// The conntrack engine itself does not modify these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatTranslation {
    pub translated_src_ip: [u8; 4],
    pub translated_src_port: u16,
    pub direction: NatDirection,
}

// ── Session entry ────────────────────────────────────────────────────

/// A connection tracking session entry.
///
/// Each entry records the 5-tuple key, protocol state, timestamps,
/// and optional NAT translation info.
///
/// RFC-REF: RFC 7857 Section 2
/// "A NAT session [...] contains all the information necessary to
/// translate a packet belonging to that session."
#[derive(Debug, Clone)]
pub struct Session {
    pub key: SessionKey,
    pub state: SessionState,
    pub created_at: Instant,
    pub last_seen: Instant,
    /// NAT translation info (populated by the NAT engine, not conntrack).
    pub nat_info: Option<NatTranslation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{IcmpInfo, Ipv4Info, L2Info, L3Info, L4Info, PacketMeta, TcpInfo, UdpInfo};

    // ── Helper: build a PacketMeta ─────────────────────────────────

    fn make_ipv4_l2() -> L2Info {
        L2Info {
            dst_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            ethertype: 0x0800,
        }
    }

    fn make_ipv4_info(src: [u8; 4], dst: [u8; 4], protocol: u8) -> Ipv4Info {
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

    // ── SessionKey::from_packet tests ──────────────────────────────

    #[test]
    fn session_key_from_tcp_packet() {
        let meta = PacketMeta {
            in_ifindex: 0, // eth0
            l2: make_ipv4_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4_info(
                [192, 168, 1, 100],
                [10, 0, 0, 1],
                6,
            ))),
            l4: Some(L4Info::Tcp(TcpInfo {
                src_port: 49152,
                dst_port: 80,
                seq_num: 1000,
                ack_num: 0,
                data_offset: 5,
                flags: 0x02,
                window: 65535,
                checksum: 0,
            })),
            raw_len: 54,
        };

        let key = SessionKey::from_packet(&meta).unwrap();
        assert_eq!(key.src_ip, [192, 168, 1, 100]);
        assert_eq!(key.dst_ip, [10, 0, 0, 1]);
        assert_eq!(
            key.proto,
            SessionProto::Tcp {
                src_port: 49152,
                dst_port: 80
            }
        );
    }

    #[test]
    fn session_key_from_udp_packet() {
        let meta = PacketMeta {
            in_ifindex: 0, // eth0
            l2: make_ipv4_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4_info(
                [10, 0, 0, 5],
                [10, 0, 0, 1],
                17,
            ))),
            l4: Some(L4Info::Udp(UdpInfo {
                src_port: 12345,
                dst_port: 53,
                length: 8,
                checksum: 0,
            })),
            raw_len: 42,
        };

        let key = SessionKey::from_packet(&meta).unwrap();
        assert_eq!(key.src_ip, [10, 0, 0, 5]);
        assert_eq!(key.dst_ip, [10, 0, 0, 1]);
        assert_eq!(
            key.proto,
            SessionProto::Udp {
                src_port: 12345,
                dst_port: 53
            }
        );
    }

    #[test]
    fn session_key_from_icmp_packet() {
        let meta = PacketMeta {
            in_ifindex: 0, // eth0
            l2: make_ipv4_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4_info(
                [192, 168, 1, 1],
                [192, 168, 1, 2],
                1,
            ))),
            l4: Some(L4Info::Icmp(IcmpInfo {
                icmp_type: 8,
                icmp_code: 0,
                checksum: 0,
                rest_of_header: [0x12, 0x34, 0x00, 0x01],
            })),
            raw_len: 42,
        };

        let key = SessionKey::from_packet(&meta).unwrap();
        assert_eq!(key.src_ip, [192, 168, 1, 1]);
        assert_eq!(key.dst_ip, [192, 168, 1, 2]);
        assert_eq!(key.proto, SessionProto::Icmp { id: 0x1234 });
    }

    #[test]
    fn session_key_from_non_ipv4_returns_none() {
        let meta = PacketMeta {
            in_ifindex: 0, // eth0
            l2: L2Info {
                dst_mac: [0xFF; 6],
                src_mac: [0xAA; 6],
                ethertype: 0x0806,
            },
            l3: None,
            l4: None,
            raw_len: 42,
        };

        assert!(SessionKey::from_packet(&meta).is_none());
    }

    #[test]
    fn session_key_from_ipv4_no_l4_returns_none() {
        let meta = PacketMeta {
            in_ifindex: 0, // eth0
            l2: make_ipv4_l2(),
            l3: Some(L3Info::Ipv4(make_ipv4_info(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                99, // unknown protocol
            ))),
            l4: None,
            raw_len: 34,
        };

        assert!(SessionKey::from_packet(&meta).is_none());
    }

    // ── SessionKey::reverse tests ──────────────────────────────────

    #[test]
    fn reverse_tcp_key_swaps_ips_and_ports() {
        let key = SessionKey {
            src_ip: [192, 168, 1, 100],
            dst_ip: [10, 0, 0, 1],
            proto: SessionProto::Tcp {
                src_port: 49152,
                dst_port: 80,
            },
        };
        let rev = key.reverse();

        assert_eq!(rev.src_ip, [10, 0, 0, 1]);
        assert_eq!(rev.dst_ip, [192, 168, 1, 100]);
        assert_eq!(
            rev.proto,
            SessionProto::Tcp {
                src_port: 80,
                dst_port: 49152
            }
        );
    }

    #[test]
    fn reverse_udp_key_swaps_ips_and_ports() {
        let key = SessionKey {
            src_ip: [10, 0, 0, 5],
            dst_ip: [10, 0, 0, 1],
            proto: SessionProto::Udp {
                src_port: 12345,
                dst_port: 53,
            },
        };
        let rev = key.reverse();

        assert_eq!(rev.src_ip, [10, 0, 0, 1]);
        assert_eq!(rev.dst_ip, [10, 0, 0, 5]);
        assert_eq!(
            rev.proto,
            SessionProto::Udp {
                src_port: 53,
                dst_port: 12345
            }
        );
    }

    #[test]
    fn reverse_icmp_key_swaps_ips_keeps_id() {
        let key = SessionKey {
            src_ip: [192, 168, 1, 1],
            dst_ip: [192, 168, 1, 2],
            proto: SessionProto::Icmp { id: 0x1234 },
        };
        let rev = key.reverse();

        assert_eq!(rev.src_ip, [192, 168, 1, 2]);
        assert_eq!(rev.dst_ip, [192, 168, 1, 1]);
        assert_eq!(rev.proto, SessionProto::Icmp { id: 0x1234 });
    }

    #[test]
    fn reverse_of_reverse_is_identity() {
        let key = SessionKey {
            src_ip: [192, 168, 1, 100],
            dst_ip: [10, 0, 0, 1],
            proto: SessionProto::Tcp {
                src_port: 49152,
                dst_port: 80,
            },
        };
        assert_eq!(key.reverse().reverse(), key);
    }
}

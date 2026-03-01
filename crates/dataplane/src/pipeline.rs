//! Pipeline processing orchestration for the ruster dataplane.
//!
//! Processes a single packet through the forwarding path:
//!
//! ```text
//! PRE_ROUTING(DNAT) -> conntrack -> L3 route -> firewall(FORWARD) -> POST_ROUTING(SNAT) -> forward/drop
//! ```
//!
//! The main entry point is [`process_packet`], which takes a raw packet
//! and references to the forwarding engines, then returns a
//! [`PipelineResult`] indicating whether the packet should be forwarded,
//! dropped, or was consumed internally.
//!
//! RFC-REF: RFC 3022 Section 4.2
//! "The processing order ensures that DNAT is applied before routing
//! (PRE_ROUTING) and SNAT is applied after routing (POST_ROUTING)."

use std::collections::HashMap;

use crate::conntrack::session::{SessionKey, SessionState, TcpState};
use crate::conntrack::{ConntrackEngine, ConntrackError};
use crate::firewall::{FirewallEngine, FwChain, FwContext, FwVerdict};
use crate::icmp::{self, IcmpReply};
use crate::icmpv6;
use crate::io::RawPacket;
use crate::l2::bridge::L2Decision;
use crate::l2::L2Engine;
use crate::nat::{NatAction, NatEngine};
use crate::nd::{NdAction, NdEngine};
use crate::packet;
use crate::packet::{L3Info, L4Info};
use crate::routing::ipv6_table::Ipv6RouteTable;
use crate::routing::{L3Decision, L3DropReason, L3Engine};
use crate::srv6::{Srv6Decision, Srv6Engine};

use ruster_config::model::{FirewallZone, InterfaceConfig, InterfaceZone};

// ── Zone resolver ─────────────────────────────────────────────────

/// Maps interface names to their firewall zones.
#[derive(Debug, Clone)]
pub struct ZoneResolver {
    zones: HashMap<String, FirewallZone>,
}

impl ZoneResolver {
    /// Build a zone resolver from interface configuration.
    pub fn from_config(interfaces: &[InterfaceConfig]) -> Self {
        let zones = interfaces
            .iter()
            .map(|iface| {
                let zone = match iface.zone {
                    InterfaceZone::Lan => FirewallZone::Lan,
                    InterfaceZone::Wan => FirewallZone::Wan,
                };
                (iface.name.clone(), zone)
            })
            .collect();
        Self { zones }
    }

    /// Resolve the firewall zone for a given interface name.
    /// Returns `FirewallZone::Lan` as default if the interface is not found.
    pub fn resolve(&self, iface: &str) -> FirewallZone {
        self.zones.get(iface).copied().unwrap_or(FirewallZone::Lan)
    }
}

// ── Pipeline result types ───────────────────────────────────────────

/// Result of processing a single packet through the pipeline.
#[derive(Debug)]
pub enum PipelineResult {
    /// Packet should be forwarded out the given interface.
    Forward {
        /// Name of the egress interface.
        egress_iface: String,
        /// New TTL after L3 decrement (Some for L3 forwarded packets, None for L2-only).
        new_ttl: Option<u8>,
        /// Next-hop IPv4 address (Some for L3 forwarded packets, None for L2-only).
        next_hop: Option<[u8; 4]>,
        /// NAT translation to apply (SNAT or DNAT), if any.
        nat: NatResult,
    },
    /// Packet should be forwarded out the given interface (IPv6 path).
    ///
    /// RFC-REF: RFC 8200 Section 3
    /// IPv6 forwarding uses a 128-bit next-hop address and hop-limit
    /// decrement (no header checksum to update).
    ForwardV6 {
        /// Name of the egress interface.
        egress_iface: String,
        /// New Hop Limit after decrement.
        new_hop_limit: u8,
        /// Next-hop IPv6 address.
        next_hop_v6: [u8; 16],
        /// If SRv6 processing updated the DA, the new destination address
        /// to write into the packet's IPv6 header (bytes 24..40).
        srv6_new_da: Option<[u8; 16]>,
        /// If SRv6 processing modified the SRH, `(srh_offset, new_sl)` for rewriting.
        ///
        /// RFC-REF: RFC 8986 Section 4.1
        /// "Decrement SL" — the SRH Segments Left field must be
        /// rewritten in the wire packet for downstream SRv6 nodes.
        srv6_srh_rewrite: Option<(usize, u8)>,
    },
    /// SRv6 decapsulated inner IPv4 packet to re-inject into the pipeline.
    ///
    /// RFC-REF: RFC 8986 Section 4.1.4
    /// "Pop the outer IPv6 header with all its extension headers and
    /// submit the inner IPv4 packet to the IPv4 FIB."
    DecapToIpv4 {
        /// Byte offset of the inner IPv4 packet within the Ethernet frame.
        inner_offset: usize,
    },
    /// SRv6 decapsulated inner IPv6 packet to re-inject into the pipeline.
    ///
    /// RFC-REF: RFC 8986 Section 4.1.5
    /// "Pop the outer IPv6 header with all its extension headers and
    /// submit the inner IPv6 packet to the IPv6 FIB."
    DecapToIpv6 {
        /// Byte offset of the inner IPv6 packet within the Ethernet frame.
        inner_offset: usize,
    },
    /// Packet should be flooded to all listed interfaces (L2 unknown
    /// unicast or broadcast within a bridge domain).
    Flood {
        /// Names of the egress interfaces (excludes the ingress port).
        egress_ifaces: Vec<String>,
    },
    /// Packet was dropped.
    Drop {
        /// Why the packet was dropped.
        reason: DropReason,
        /// Optional ICMP error reply to send back to the original sender.
        /// Present for TTL expired and no-route drops (when the original
        /// packet is not itself ICMP).
        icmp_reply: Option<IcmpReply>,
    },
    /// Packet was consumed (e.g., ARP reply generated internally).
    Consumed,
    /// An ND Neighbor Advertisement reply should be sent.
    ///
    /// The run loop is responsible for constructing the NA packet from
    /// the reply info and transmitting it on the specified interface.
    NdReply {
        /// Interface to send the reply on.
        egress_iface: String,
        /// NA reply fields needed to build the response packet.
        reply_info: crate::nd::NaReplyInfo,
    },
}

/// NAT translation result communicated from the pipeline to the run loop.
///
/// When the pipeline decides a packet needs NAT, it returns a
/// `NatResult` alongside the forwarding decision. The run loop is
/// responsible for applying the actual byte-level rewrite using
/// `rewrite::rewrite_snat` or `rewrite::rewrite_dnat`.
///
/// RFC-REF: RFC 3022 Section 4.2
/// "DNAT in PRE_ROUTING, SNAT in POST_ROUTING."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatResult {
    /// Apply SNAT: rewrite source IP/port on the outgoing packet.
    Snat {
        new_src_ip: [u8; 4],
        new_src_port: u16,
    },
    /// Apply DNAT: rewrite destination IP/port on the outgoing packet.
    Dnat {
        new_dst_ip: [u8; 4],
        new_dst_port: u16,
    },
    /// No NAT translation needed.
    None,
}

/// Reason a packet was dropped during pipeline processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// The raw bytes could not be parsed into a valid packet.
    ParseError,
    /// L2 engine dropped the packet.
    L2Drop,
    /// L3 engine found no matching route.
    L3NoRoute,
    /// L3 engine detected TTL expiration.
    L3TtlExpired,
    /// L3 engine received a non-IPv4 packet.
    L3NotIpv4,
    /// IPv6 Hop Limit expired.
    L3HopLimitExpired,
    /// Firewall dropped the packet.
    FirewallDrop,
    /// NAT engine dropped the packet.
    NatDrop,
    /// Conntrack session table is full.
    ConntrackTableFull,
    /// SRv6 processing dropped the packet.
    Srv6Drop(crate::srv6::Srv6DropReason),
}

// ── Pipeline function ───────────────────────────────────────────────

/// Result of a conntrack lookup/create attempt for the pipeline.
///
/// Used internally by [`process_packet`] to communicate conntrack
/// state to downstream stages (firewall, NAT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackResult {
    /// Existing session matched (forward or reverse direction).
    Existing,
    /// New session was created.
    Created,
    /// Session table is full; the packet should be dropped.
    TableFull,
    /// Packet is not trackable (non-IPv4 or no L4 header).
    Untracked,
}

/// Process a single raw packet through the forwarding pipeline.
///
/// The processing flow is:
/// 1. Parse the raw bytes into a [`PacketMeta`](packet::PacketMeta).
/// 2. If parsing fails, return `Drop(ParseError)`.
/// 3. **L2 check**: if the ingress interface belongs to a bridge domain:
///    a. Learn source MAC (FDB update).
///    b. If the destination IP is one of the router's local IPs,
///    fall through to L3 processing.
///    c. Otherwise, make an L2 forwarding decision:
///    Known unicast -> `Forward` to the learned port.
///    Unknown unicast / broadcast -> `Flood` to all bridge domain
///    ports except ingress.
///    Same-port drop -> `Drop(L2Drop)`.
/// 4. If the interface is **not** in a bridge domain, proceed to L3.
/// 5. **Conntrack lookup/create**: for every trackable packet, look up
///    both forward and reverse session keys. Create a new session for
///    new flows; update TCP state and refresh timestamps for existing
///    sessions.
/// 6. Check L3 routing via [`L3Engine::process`] (IPv4) or the IPv6
///    forwarding path (ND check -> route lookup -> forward).
/// 7. Based on the L3 decision:
///    - `Forward { .. }` -> check firewall -> `Forward` or `Drop(FirewallDrop)`.
///    - `LocalDelivery` -> `Consumed`.
///    - `Drop(reason)` -> `Drop` with a mapped reason.
#[allow(clippy::too_many_arguments)]
pub fn process_packet(
    raw_pkt: &RawPacket,
    l2: &mut L2Engine,
    l3: &L3Engine,
    firewall: &FirewallEngine,
    conntrack: &mut ConntrackEngine,
    nat: &mut NatEngine,
    zone_resolver: &ZoneResolver,
    iface_macs: &std::collections::HashMap<String, [u8; 6]>,
) -> PipelineResult {
    process_packet_v6(
        raw_pkt,
        l2,
        l3,
        firewall,
        conntrack,
        nat,
        zone_resolver,
        iface_macs,
        None,
        None,
        None,
    )
}

/// Process a single raw packet with optional IPv6 engine support.
///
/// When `nd` and `ipv6_routes` are `Some`, IPv6 packets are forwarded
/// through the ND resolution + LPM route lookup path. When they are
/// `None`, IPv6 packets fall through to the IPv4 L3 engine which will
/// return `Drop(NotIpv4)`.
///
/// When `srv6` is `Some`, IPv6 packets with DA matching a local SID
/// are processed through the SRv6 engine before normal IPv6 forwarding.
///
/// RFC-REF: RFC 8200 Section 3
/// IPv6 forwarding is based on the 128-bit destination address;
/// Hop Limit is decremented and the packet is forwarded or dropped.
#[allow(clippy::too_many_arguments)]
pub fn process_packet_v6(
    raw_pkt: &RawPacket,
    l2: &mut L2Engine,
    l3: &L3Engine,
    firewall: &FirewallEngine,
    conntrack: &mut ConntrackEngine,
    nat: &mut NatEngine,
    zone_resolver: &ZoneResolver,
    iface_macs: &std::collections::HashMap<String, [u8; 6]>,
    nd: Option<&mut NdEngine>,
    ipv6_routes: Option<&Ipv6RouteTable>,
    srv6: Option<&Srv6Engine>,
) -> PipelineResult {
    // Step 1: Parse raw bytes.
    let mut meta = match packet::parse_packet(&raw_pkt.data, &raw_pkt.ingress_iface) {
        Ok(m) => m,
        Err(_) => {
            return PipelineResult::Drop {
                reason: DropReason::ParseError,
                icmp_reply: None,
            }
        }
    };

    // Step 2: L2 bridge domain processing.
    if l2.is_bridged(&meta.in_ifname) {
        let l2_decision = l2.process(&meta);

        // Check whether the packet should be punted to L3 processing.
        // This happens when either:
        // - The destination IP is one of the router's own IPs (local delivery), OR
        // - The destination MAC matches the router's MAC on the ingress interface
        //   (transit routing — the host is using us as the default gateway).
        let is_local_ip = match &meta.l3 {
            Some(L3Info::Ipv4(ipv4)) => l3.is_local_ip(&ipv4.dst_addr),
            Some(L3Info::Ipv6(ipv6)) => nd
                .as_ref()
                .map(|engine| engine.is_local_ipv6(&ipv6.dst_addr))
                .unwrap_or(false),
            _ => false,
        };
        let is_router_mac = iface_macs
            .get(&meta.in_ifname)
            .is_some_and(|our_mac| meta.l2.dst_mac == *our_mac);
        let is_local = is_local_ip || is_router_mac;

        if !is_local {
            // Pure L2 forwarding — do not enter L3.
            return match l2_decision {
                L2Decision::Unicast { out_ifname } => PipelineResult::Forward {
                    egress_iface: out_ifname,
                    new_ttl: None,
                    next_hop: None,
                    nat: NatResult::None,
                },
                L2Decision::Flood { out_ifnames } => PipelineResult::Flood {
                    egress_ifaces: out_ifnames,
                },
                L2Decision::Drop => PipelineResult::Drop {
                    reason: DropReason::L2Drop,
                    icmp_reply: None,
                },
            };
        }
        // else: packet is for our local IP -> fall through to L3.
    }

    // ── IPv6 path ──────────────────────────────────────────────────────
    //
    // RFC-REF: RFC 8200 Section 3
    // If the packet is IPv6 and we have IPv6 engines, process it through
    // the IPv6-specific forwarding path: ND check -> route lookup.
    if let Some(L3Info::Ipv6(ref ipv6)) = meta.l3 {
        if let (Some(nd_engine), Some(route_table)) = (nd, ipv6_routes) {
            return process_ipv6_packet(
                raw_pkt,
                &meta,
                ipv6,
                nd_engine,
                route_table,
                firewall,
                conntrack,
                zone_resolver,
                srv6,
            );
        }
        // No IPv6 engines -> fall through to IPv4 L3 which will return NotIpv4.
    }

    // ── IPv4 path ──────────────────────────────────────────────────────
    //
    // NAT integration follows the netfilter-style processing order:
    //   PRE_ROUTING(DNAT/hairpin) -> conntrack -> routing -> FORWARD(FW) -> POST_ROUTING(SNAT)
    //
    // RFC-REF: RFC 3022 Section 4.2
    // "Destination NAT is performed before the routing decision,
    // source NAT after."

    // Step 3: PRE_ROUTING — DNAT / hairpin NAT.
    //
    // Check if the packet needs destination translation before routing.
    // Hairpin is checked first (LAN -> external IP -> internal server),
    // then inbound DNAT (WAN -> internal server via port forward or
    // reverse translation of outbound session return traffic).
    let pre_routing_nat = {
        let hairpin_action = nat.process_hairpin(&meta, conntrack);
        if hairpin_action != NatAction::PassThrough {
            hairpin_action
        } else {
            nat.process_inbound(&meta, conntrack)
        }
    };

    // If DNAT drops the packet (e.g. conntrack table full), bail out.
    if pre_routing_nat == NatAction::Drop {
        return PipelineResult::Drop {
            reason: DropReason::NatDrop,
            icmp_reply: None,
        };
    }

    // Build the DNAT result to be carried through the pipeline.
    // The actual packet rewrite is deferred to the run loop.
    let dnat_result = match &pre_routing_nat {
        NatAction::Dnat {
            new_dst_ip,
            new_dst_port,
        } => NatResult::Dnat {
            new_dst_ip: *new_dst_ip,
            new_dst_port: *new_dst_port,
        },
        _ => NatResult::None,
    };

    // After DNAT is determined, update the packet metadata so that the
    // L3 routing decision uses the translated destination IP/port.
    // Without this, port forwarding is broken: the original dst_ip is
    // the router's WAN IP, so routing would return LocalDelivery instead
    // of Forward to the internal server.
    //
    // RFC-REF: RFC 3022 Section 4.2
    // "Destination NAT is performed before the routing decision."
    if let NatResult::Dnat {
        new_dst_ip,
        new_dst_port,
    } = &dnat_result
    {
        if let Some(L3Info::Ipv4(ref mut ipv4)) = meta.l3 {
            ipv4.dst_addr = *new_dst_ip;
        }
        match &mut meta.l4 {
            Some(L4Info::Tcp(ref mut tcp)) => {
                tcp.dst_port = *new_dst_port;
            }
            Some(L4Info::Udp(ref mut udp)) => {
                udp.dst_port = *new_dst_port;
            }
            _ => {}
        }
    }

    // Step 4: Conntrack lookup/create.
    //
    // For every trackable packet (IPv4 with TCP/UDP/ICMP L4 header),
    // perform a session lookup. If a forward or reverse session exists,
    // update its state and refresh the timestamp. Otherwise, create a
    // new session for the flow.
    let ct_result = conntrack_process(&meta, conntrack);

    // If the session table is full, drop the packet immediately.
    if ct_result == ConntrackResult::TableFull {
        return PipelineResult::Drop {
            reason: DropReason::ConntrackTableFull,
            icmp_reply: None,
        };
    }

    // Step 5: L3 routing decision.
    let l3_decision = l3.process(&meta);

    match l3_decision {
        L3Decision::Forward {
            out_ifname,
            next_hop,
            new_ttl,
        } => {
            // Step 6: Firewall check on the FORWARD chain.
            let src_zone = zone_resolver.resolve(&raw_pkt.ingress_iface);
            let dst_zone = zone_resolver.resolve(&out_ifname);
            let is_new_session = matches!(
                ct_result,
                ConntrackResult::Created | ConntrackResult::Untracked
            );
            let fw_ctx = FwContext::from_packet(
                &meta,
                FwChain::Forward,
                src_zone,
                dst_zone,
                conntrack,
                is_new_session,
            );
            let verdict = firewall.evaluate(&fw_ctx);

            match verdict {
                FwVerdict::Accept | FwVerdict::AcceptRule { .. } => {
                    // Step 7: POST_ROUTING — SNAT (masquerade).
                    //
                    // If a DNAT was already applied in PRE_ROUTING, we carry it
                    // forward. Otherwise, check if outbound SNAT is needed.
                    //
                    // RFC-REF: RFC 3022 Section 2.2
                    // "NAPT extends the notion of translation one step further."
                    let nat_result = if dnat_result != NatResult::None {
                        dnat_result
                    } else {
                        // Check if outbound SNAT applies (LAN -> WAN).
                        let snat_action = nat.process_outbound(&meta, conntrack);
                        match snat_action {
                            NatAction::Snat {
                                new_src_ip,
                                new_src_port,
                            } => NatResult::Snat {
                                new_src_ip,
                                new_src_port,
                            },
                            NatAction::Drop => {
                                return PipelineResult::Drop {
                                    reason: DropReason::NatDrop,
                                    icmp_reply: None,
                                };
                            }
                            _ => NatResult::None,
                        }
                    };

                    PipelineResult::Forward {
                        egress_iface: out_ifname,
                        new_ttl: Some(new_ttl),
                        next_hop: Some(next_hop),
                        nat: nat_result,
                    }
                }
                FwVerdict::Drop | FwVerdict::DropRule { .. } => PipelineResult::Drop {
                    reason: DropReason::FirewallDrop,
                    icmp_reply: None,
                },
            }
        }
        L3Decision::LocalDelivery => PipelineResult::Consumed,
        L3Decision::Drop { reason } => {
            let drop_reason = map_l3_drop_reason(reason);
            let icmp_reply = match drop_reason {
                DropReason::L3TtlExpired => {
                    let router_ip = l3.router_ip_for_iface(&raw_pkt.ingress_iface);
                    router_ip.and_then(|ip| {
                        icmp::generate_icmp_error(
                            &raw_pkt.data,
                            icmp::IcmpError::TtlExceeded,
                            ip,
                            &raw_pkt.ingress_iface,
                        )
                    })
                }
                DropReason::L3NoRoute => {
                    let router_ip = l3.router_ip_for_iface(&raw_pkt.ingress_iface);
                    router_ip.and_then(|ip| {
                        icmp::generate_icmp_error(
                            &raw_pkt.data,
                            icmp::IcmpError::NetUnreachable,
                            ip,
                            &raw_pkt.ingress_iface,
                        )
                    })
                }
                // No ICMP for non-IPv4 drops or other reasons.
                _ => None,
            };
            PipelineResult::Drop {
                reason: drop_reason,
                icmp_reply,
            }
        }
    }
}

/// Perform conntrack lookup/create/update for a single packet.
///
/// This is called on every packet entering the L3 processing path.
/// The logic:
/// 1. Extract a session key from the packet. If the packet is not
///    trackable (non-IPv4, no L4 header), return `Untracked`.
/// 2. Look up the forward key. If found, update TCP state and touch.
/// 3. Look up the reverse key. If found, update TCP state and touch.
/// 4. If neither direction is found, create a new session with the
///    appropriate initial state.
/// 5. If the table is full, return `TableFull`.
fn conntrack_process(
    meta: &packet::PacketMeta,
    conntrack: &mut ConntrackEngine,
) -> ConntrackResult {
    let forward_key = match SessionKey::from_packet(meta) {
        Some(k) => k,
        None => return ConntrackResult::Untracked,
    };

    let reverse_key = forward_key.reverse();

    // Check forward direction.
    if conntrack.lookup(&forward_key).is_some() {
        // Update TCP state machine if applicable.
        if let Some(L4Info::Tcp(tcp)) = &meta.l4 {
            conntrack.update_tcp_state(&forward_key, tcp.flags);
        }
        conntrack.touch(&forward_key);
        return ConntrackResult::Existing;
    }

    // Check reverse direction (return traffic).
    if conntrack.lookup(&reverse_key).is_some() {
        // Update TCP state machine on the original session.
        if let Some(L4Info::Tcp(tcp)) = &meta.l4 {
            conntrack.update_tcp_state(&reverse_key, tcp.flags);
        }
        conntrack.touch(&reverse_key);
        return ConntrackResult::Existing;
    }

    // New flow: create a session.
    let state = initial_session_state(meta);
    match conntrack.create_session(forward_key, state) {
        Ok(_) => ConntrackResult::Created,
        Err(ConntrackError::TableFull) => ConntrackResult::TableFull,
    }
}

/// Determine the initial session state from packet metadata.
fn initial_session_state(meta: &packet::PacketMeta) -> SessionState {
    match &meta.l4 {
        Some(L4Info::Tcp(_)) => SessionState::Tcp(TcpState::SynSent),
        Some(L4Info::Udp(_)) => SessionState::Udp,
        Some(L4Info::Icmp(_)) => SessionState::Icmp,
        // ICMPv6 conntrack uses the same Icmp state (not yet fully tracked).
        Some(L4Info::Icmpv6(_)) => SessionState::Icmp,
        None => SessionState::Udp, // fallback, should not happen for tracked packets
    }
}

/// Process an IPv6 packet through SRv6, ND, and route lookup.
///
/// RFC-REF: RFC 8200 Section 3
/// RFC-REF: RFC 8986 Section 4 (SRv6 SID processing)
///
/// Processing order:
/// 1. Check if this is an ND message (NS/NA) and process via NdEngine.
/// 2. Check if the destination is one of our local IPv6 addresses.
/// 3. If SRv6 is enabled: check DA against Local SID table.
/// 4. Check Hop Limit (must be > 1 to forward).
/// 5. Perform LPM route lookup in the IPv6 route table.
/// 6. Return ForwardV6 or Drop.
#[allow(clippy::too_many_arguments)]
fn process_ipv6_packet(
    raw_pkt: &RawPacket,
    meta: &packet::PacketMeta,
    ipv6: &packet::Ipv6Info,
    nd_engine: &mut NdEngine,
    route_table: &Ipv6RouteTable,
    firewall: &FirewallEngine,
    conntrack: &ConntrackEngine,
    zone_resolver: &ZoneResolver,
    srv6: Option<&Srv6Engine>,
) -> PipelineResult {
    // Step 1: Check if this is an ND message.
    if let Some(packet::L4Info::Icmpv6(ref icmpv6)) = meta.l4 {
        if icmpv6.nd.is_some() {
            let nd_action = nd_engine.process_nd(meta);
            return match nd_action {
                NdAction::Reply { out_ifname, packet } => PipelineResult::NdReply {
                    egress_iface: out_ifname,
                    reply_info: packet,
                },
                // NA updates, drops, or other ND actions are consumed.
                _ => PipelineResult::Consumed,
            };
        }
    }

    // Step 2: Check for local delivery.
    if nd_engine.is_local_ipv6(&ipv6.dst_addr) {
        return PipelineResult::Consumed;
    }

    // Step 3: SRv6 processing.
    //
    // RFC-REF: RFC 8986 Section 4
    // If the destination matches a local SID, execute the bound action.
    // SRv6 processing happens before normal IPv6 forwarding so that
    // SRv6 endpoints can modify the DA or decapsulate before routing.
    if let Some(srv6_engine) = srv6 {
        if srv6_engine.is_enabled() {
            let payload = if ipv6.payload_offset <= raw_pkt.data.len() {
                &raw_pkt.data[ipv6.payload_offset..]
            } else {
                &[]
            };

            let decision = srv6_engine.process(
                &ipv6.dst_addr,
                ipv6.next_header,
                payload,
                ipv6.hop_limit,
                ipv6.payload_offset,
            );

            match decision {
                Srv6Decision::Forward {
                    new_da,
                    srh_modified,
                    new_sl,
                } => {
                    // Build SRH rewrite info for the worker to apply.
                    let srh_rewrite = if srh_modified {
                        new_sl.map(|sl| (ipv6.payload_offset, sl))
                    } else {
                        None
                    };

                    // The SRv6 engine updated the DA. Route the packet
                    // using the new DA via normal IPv6 forwarding.
                    // The new_da will be written into the IPv6 header by the caller.
                    // Hop limit check and route lookup use the new DA.
                    if ipv6.hop_limit <= 1 {
                        let icmp_reply = nd_engine
                            .local_ipv6_for_iface(&raw_pkt.ingress_iface)
                            .and_then(|router_ip| {
                                icmpv6::generate_icmpv6_error(
                                    &raw_pkt.data,
                                    icmpv6::Icmpv6Error::HopLimitExceeded,
                                    router_ip,
                                    &raw_pkt.ingress_iface,
                                )
                            });
                        return PipelineResult::Drop {
                            reason: DropReason::L3HopLimitExpired,
                            icmp_reply,
                        };
                    }
                    let route = match route_table.lookup(&new_da) {
                        Some(entry) => entry,
                        None => {
                            let icmp_reply = nd_engine
                                .local_ipv6_for_iface(&raw_pkt.ingress_iface)
                                .and_then(|router_ip| {
                                    icmpv6::generate_icmpv6_error(
                                        &raw_pkt.data,
                                        icmpv6::Icmpv6Error::NoRoute,
                                        router_ip,
                                        &raw_pkt.ingress_iface,
                                    )
                                });
                            return PipelineResult::Drop {
                                reason: DropReason::L3NoRoute,
                                icmp_reply,
                            };
                        }
                    };
                    let out_ifname = route.out_ifname.clone();
                    let next_hop_v6 = route.next_hop;
                    let new_hop_limit = ipv6.hop_limit - 1;

                    // Firewall check.
                    let src_zone = zone_resolver.resolve(&raw_pkt.ingress_iface);
                    let dst_zone = zone_resolver.resolve(&out_ifname);
                    let fw_ctx = FwContext::from_packet(
                        meta,
                        FwChain::Forward,
                        src_zone,
                        dst_zone,
                        conntrack,
                        true,
                    );
                    let verdict = firewall.evaluate(&fw_ctx);

                    return match verdict {
                        FwVerdict::Accept | FwVerdict::AcceptRule { .. } => {
                            PipelineResult::ForwardV6 {
                                egress_iface: out_ifname,
                                new_hop_limit,
                                next_hop_v6,
                                srv6_new_da: Some(new_da),
                                srv6_srh_rewrite: srh_rewrite,
                            }
                        }
                        FwVerdict::Drop | FwVerdict::DropRule { .. } => PipelineResult::Drop {
                            reason: DropReason::FirewallDrop,
                            icmp_reply: None,
                        },
                    };
                }
                Srv6Decision::DecapIpv4 {
                    table: _,
                    inner_offset,
                } => {
                    return PipelineResult::DecapToIpv4 { inner_offset };
                }
                Srv6Decision::DecapIpv6 {
                    table: _,
                    inner_offset,
                } => {
                    return PipelineResult::DecapToIpv6 { inner_offset };
                }
                Srv6Decision::Drop { reason } => {
                    return PipelineResult::Drop {
                        reason: DropReason::Srv6Drop(reason),
                        icmp_reply: None,
                    };
                }
                Srv6Decision::NotSrv6 => {
                    // Not an SRv6 packet; continue with normal IPv6 forwarding.
                }
            }
        }
    }

    // Step 4: Check Hop Limit.
    // RFC-REF: RFC 8200 Section 3
    // "If [...] the Hop Limit is less than or equal to 1 [...] discard
    // the packet and originate an ICMPv6 Time Exceeded message."
    //
    // RFC-REF: RFC 4443 Section 3.3
    // Generate ICMPv6 Time Exceeded (Type 3, Code 0) when hop limit
    // reaches zero during forwarding.
    if ipv6.hop_limit <= 1 {
        let icmp_reply = nd_engine
            .local_ipv6_for_iface(&raw_pkt.ingress_iface)
            .and_then(|router_ip| {
                icmpv6::generate_icmpv6_error(
                    &raw_pkt.data,
                    icmpv6::Icmpv6Error::HopLimitExceeded,
                    router_ip,
                    &raw_pkt.ingress_iface,
                )
            });
        return PipelineResult::Drop {
            reason: DropReason::L3HopLimitExpired,
            icmp_reply,
        };
    }

    // Step 5: Route lookup.
    //
    // RFC-REF: RFC 4443 Section 3.1
    // Generate ICMPv6 Destination Unreachable (Type 1, Code 0) when
    // no route matches the destination address.
    let route = match route_table.lookup(&ipv6.dst_addr) {
        Some(entry) => entry,
        None => {
            let icmp_reply = nd_engine
                .local_ipv6_for_iface(&raw_pkt.ingress_iface)
                .and_then(|router_ip| {
                    icmpv6::generate_icmpv6_error(
                        &raw_pkt.data,
                        icmpv6::Icmpv6Error::NoRoute,
                        router_ip,
                        &raw_pkt.ingress_iface,
                    )
                });
            return PipelineResult::Drop {
                reason: DropReason::L3NoRoute,
                icmp_reply,
            };
        }
    };

    let out_ifname = route.out_ifname.clone();
    let next_hop_v6 = route.next_hop;
    let new_hop_limit = ipv6.hop_limit - 1;

    // Step 6: Firewall check.
    let src_zone = zone_resolver.resolve(&raw_pkt.ingress_iface);
    let dst_zone = zone_resolver.resolve(&out_ifname);
    // IPv6 conntrack is not yet implemented — all IPv6 packets are
    // treated as new / untracked sessions for firewall purposes.
    let fw_ctx =
        FwContext::from_packet(meta, FwChain::Forward, src_zone, dst_zone, conntrack, true);
    let verdict = firewall.evaluate(&fw_ctx);

    match verdict {
        FwVerdict::Accept | FwVerdict::AcceptRule { .. } => PipelineResult::ForwardV6 {
            egress_iface: out_ifname,
            new_hop_limit,
            next_hop_v6,
            srv6_new_da: None,
            srv6_srh_rewrite: None,
        },
        FwVerdict::Drop | FwVerdict::DropRule { .. } => PipelineResult::Drop {
            reason: DropReason::FirewallDrop,
            icmp_reply: None,
        },
    }
}

/// Map an L3 drop reason to a pipeline drop reason.
fn map_l3_drop_reason(reason: L3DropReason) -> DropReason {
    match reason {
        L3DropReason::NotIpv4 => DropReason::L3NotIpv4,
        L3DropReason::TtlExpired => DropReason::L3TtlExpired,
        L3DropReason::NoRoute => DropReason::L3NoRoute,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::{ConntrackConfig, ConntrackEngine};
    use crate::io::RawPacket;
    use crate::l2::L2Engine;
    use crate::nat::NatEngine;
    use ruster_config::model::{
        BridgeDomain, DefaultPolicy, FirewallConfig, InterfaceConfig, InterfaceRole, InterfaceZone,
        L2Config, NatConfig, NatMode, RoutingConfig, StaticRoute,
    };

    // ── Test helpers ────────────────────────────────────────────────

    /// Create an L2 engine with **no** bridge domains, so all interfaces
    /// skip L2 processing and go directly to L3.  This preserves the
    /// behaviour of every pre-existing pipeline test.
    fn make_l2_engine_empty() -> L2Engine {
        L2Engine::from_config(&L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            arp_hold_queue_per_ip: 3,
            arp_hold_queue_max: 1024,
            bridge_domains: vec![],
        })
    }

    fn make_routing_config() -> RoutingConfig {
        RoutingConfig {
            ipv4_static_routes: vec![
                StaticRoute {
                    prefix: "0.0.0.0/0".to_string(),
                    next_hop: "10.0.0.1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                StaticRoute {
                    prefix: "192.168.1.0/24".to_string(),
                    next_hop: "0.0.0.0".to_string(),
                    out_if: "lan0".to_string(),
                    metric: 10,
                },
            ],
            ipv6_static_routes: vec![],
            ospf: None,
            bgp: None,
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
                ipv6_addrs: vec![],
                zone: InterfaceZone::Wan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "lan0".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "00:AA:BB:CC:DD:EE".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
        ]
    }

    fn make_l3_engine() -> L3Engine {
        L3Engine::from_config(&make_routing_config(), &make_interfaces()).unwrap()
    }

    fn make_fw_accept_all() -> FirewallEngine {
        FirewallEngine::from_config(&FirewallConfig {
            enabled: false,
            default_input: DefaultPolicy::Accept,
            default_forward: DefaultPolicy::Accept,
            default_output: DefaultPolicy::Accept,
            allow_established_related: false,
            rules: vec![],
        })
    }

    fn make_fw_drop_all() -> FirewallEngine {
        FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Drop,
            allow_established_related: false,
            rules: vec![],
        })
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

    fn make_zone_resolver() -> ZoneResolver {
        ZoneResolver::from_config(&make_interfaces())
    }

    fn make_nat_disabled() -> NatEngine {
        NatEngine::from_config(
            &NatConfig {
                enabled: false,
                mode: NatMode::Napt44,
                external_if: "wan0".to_string(),
                hairpin: false,
                session_table_max_entries: 1000,
                tcp_established_timeout_sec: 7200,
                tcp_transitory_timeout_sec: 120,
                udp_timeout_sec: 300,
                icmp_timeout_sec: 30,
                port_forwards: vec![],
            },
            &make_interfaces(),
        )
    }

    /// Compute IPv4 header checksum and write it into the header.
    fn set_ipv4_checksum(hdr: &mut [u8]) {
        hdr[10] = 0x00;
        hdr[11] = 0x00;
        let mut sum: u32 = 0;
        for i in (0..hdr.len()).step_by(2) {
            let word = if i + 1 < hdr.len() {
                u16::from_be_bytes([hdr[i], hdr[i + 1]])
            } else {
                u16::from_be_bytes([hdr[i], 0])
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = (cksum & 0xFF) as u8;
    }

    /// Build a valid Ethernet + IPv4 + UDP packet.
    fn make_ipv4_packet(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header (20 bytes minimum)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 8; // IP header + 8 bytes UDP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(ttl);
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // Compute IPv4 checksum
        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // Minimal UDP header (8 bytes)
        pkt.extend_from_slice(&[0x00, 0x50]); // src port: 80
        pkt.extend_from_slice(&[0x00, 0x51]); // dst port: 81
        pkt.extend_from_slice(&[0x00, 0x08]); // length: 8
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum: 0
        pkt
    }

    // ── Pipeline tests ──────────────────────────────────────────────

    #[test]
    fn forward_routed_packet() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();

        // Packet from LAN to internet (8.8.8.8) -> default route via wan0.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "wan0");
            }
            other => panic!("expected Forward, got {:?}", other),
        }
    }

    #[test]
    fn drop_parse_error_too_short() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();

        // Packet too short to parse (< 14 bytes).
        let raw_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::ParseError);
            }
            other => panic!("expected Drop(ParseError), got {:?}", other),
        }
    }

    #[test]
    fn drop_no_route() {
        let mut nat = make_nat_disabled();
        // L3 engine with only a /24 route (no default route).
        let routing = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
            ipv6_static_routes: vec![],
            ospf: None,
            bgp: None,
        };
        let l3 = L3Engine::from_config(&routing, &make_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();

        // Destination 8.8.8.8 has no matching route.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3NoRoute);
            }
            other => panic!("expected Drop(L3NoRoute), got {:?}", other),
        }
    }

    #[test]
    fn drop_ttl_expired() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();

        // TTL = 1 -> after decrement would be 0, so L3 engine drops.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            1, // TTL expired
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3TtlExpired);
            }
            other => panic!("expected Drop(L3TtlExpired), got {:?}", other),
        }
    }

    #[test]
    fn consumed_local_delivery() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();

        // Destination is our local IP (10.0.0.2) -> LocalDelivery -> Consumed.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [10, 0, 0, 2], // our WAN IP
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert!(matches!(result, PipelineResult::Consumed));
    }

    #[test]
    fn drop_firewall_blocks() {
        let l3 = make_l3_engine();
        let fw = make_fw_drop_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();

        // Packet should be routed, but firewall drops everything.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::FirewallDrop);
            }
            other => panic!("expected Drop(FirewallDrop), got {:?}", other),
        }
    }

    #[test]
    fn drop_not_ipv4() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();

        // ARP packet -> L3 engine returns Drop(NotIpv4).
        let mut data = Vec::new();
        // Ethernet header
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // dst: broadcast
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src
        data.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
                                               // ARP payload (28 bytes)
        data.extend_from_slice(&[0x00, 0x01]); // HW Type: Ethernet
        data.extend_from_slice(&[0x08, 0x00]); // Proto Type: IPv4
        data.push(0x06); // HW Addr Len
        data.push(0x04); // Proto Addr Len
        data.extend_from_slice(&[0x00, 0x01]); // Operation: Request
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Sender MAC
        data.extend_from_slice(&[192, 168, 1, 1]); // Sender IP
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Target MAC
        data.extend_from_slice(&[192, 168, 1, 2]); // Target IP

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3NotIpv4);
            }
            other => panic!("expected Drop(L3NotIpv4), got {:?}", other),
        }
    }

    #[test]
    fn drop_reason_counters_can_be_tracked() {
        // This test demonstrates that pipeline results can be used to
        // accumulate per-reason drop counters.
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let mut parse_errors = 0u64;
        let mut ttl_drops = 0u64;
        let mut forwards = 0u64;

        // 1. Too-short packet -> ParseError
        let short_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };
        match process_packet(&short_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im) {
            PipelineResult::Drop {
                reason: DropReason::ParseError,
                ..
            } => parse_errors += 1,
            _ => {}
        }

        // 2. TTL=1 packet -> TtlExpired
        let ttl_data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 1);
        let ttl_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: ttl_data,
        };
        match process_packet(&ttl_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im) {
            PipelineResult::Drop {
                reason: DropReason::L3TtlExpired,
                ..
            } => ttl_drops += 1,
            _ => {}
        }

        // 3. Routable packet -> Forward
        let fwd_data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let fwd_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: fwd_data,
        };
        match process_packet(&fwd_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im) {
            PipelineResult::Forward { .. } => forwards += 1,
            _ => {}
        }

        assert_eq!(parse_errors, 1);
        assert_eq!(ttl_drops, 1);
        assert_eq!(forwards, 1);
    }

    // ── Zone resolution tests ───────────────────────────────────────

    #[test]
    fn forward_resolves_ingress_zone() {
        // Verify that the ingress interface zone is correctly resolved.
        // A packet entering from "lan0" (Lan zone) going to "wan0" (Wan zone)
        // should have src_zone=Lan. With a firewall that allows Lan->Wan,
        // the packet should be forwarded.
        use ruster_config::model::{Chain, ConnState, FirewallRule, RuleAction, RuleProto};

        let l3 = make_l3_engine();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Firewall: only allow Lan->Wan forward, drop everything else.
        let fw = FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Drop,
            allow_established_related: false,
            rules: vec![FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New],
            }],
        });

        // Packet from lan0 (Lan) to 8.8.8.8 routed via wan0 (Wan).
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "wan0");
            }
            other => panic!(
                "expected Forward (Lan->Wan should be accepted), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn forward_resolves_egress_zone() {
        // Verify that the egress interface zone is correctly resolved.
        // A packet entering from "wan0" (Wan zone) going to a LAN address
        // routed via "lan0" (Lan zone) should have src_zone=Wan, dst_zone=Lan.
        // With a firewall that only allows Lan->Wan, this should be dropped.
        use ruster_config::model::{Chain, ConnState, FirewallRule, RuleAction, RuleProto};

        let l3 = make_l3_engine();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Firewall: only allow Lan->Wan forward, drop everything else.
        let fw = FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Drop,
            allow_established_related: false,
            rules: vec![FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New],
            }],
        });

        // Packet from wan0 (Wan) to 192.168.1.100 routed via lan0 (Lan).
        // src_zone=Wan, dst_zone=Lan -> no matching rule -> drop.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "wan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::FirewallDrop);
            }
            other => panic!(
                "expected Drop(FirewallDrop) for Wan->Lan with no matching rule, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn unknown_interface_defaults_to_lan() {
        // Verify that an unknown interface name defaults to FirewallZone::Lan.
        let zr = make_zone_resolver();
        assert_eq!(zr.resolve("unknown_iface"), FirewallZone::Lan);
        assert_eq!(zr.resolve(""), FirewallZone::Lan);
    }

    // ── ICMP error generation tests ─────────────────────────────────

    #[test]
    fn ttl_expired_generates_icmp_reply() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // TTL = 1 -> L3 drops with TtlExpired -> should generate ICMP.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            1,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3TtlExpired);
                let reply = icmp_reply.expect("should generate ICMP reply for TTL expired");
                assert_eq!(reply.egress_iface, "lan0");

                // Check ICMP type/code: Time Exceeded (11, 0).
                let icmp_start = 14 + 20; // Ethernet + IPv4
                assert_eq!(reply.data[icmp_start], 11);
                assert_eq!(reply.data[icmp_start + 1], 0);

                // Check that the router IP is the lan0 IP (192.168.1.1).
                let src_ip = &reply.data[14 + 12..14 + 16];
                assert_eq!(src_ip, &[192, 168, 1, 1]);
            }
            other => panic!("expected Drop with ICMP reply, got {:?}", other),
        }
    }

    #[test]
    fn no_route_generates_icmp_reply() {
        // L3 engine with only a /24 route (no default route).
        let routing = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "192.168.1.0/24".to_string(),
                next_hop: "0.0.0.0".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
            ipv6_static_routes: vec![],
            ospf: None,
            bgp: None,
        };
        let l3 = L3Engine::from_config(&routing, &make_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Destination 8.8.8.8 has no matching route.
        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3NoRoute);
                let reply = icmp_reply.expect("should generate ICMP reply for no route");
                assert_eq!(reply.egress_iface, "lan0");

                // Check ICMP type/code: Destination Unreachable / Net Unreachable (3, 0).
                let icmp_start = 14 + 20;
                assert_eq!(reply.data[icmp_start], 3);
                assert_eq!(reply.data[icmp_start + 1], 0);
            }
            other => panic!("expected Drop with ICMP reply, got {:?}", other),
        }
    }

    #[test]
    fn no_icmp_for_icmp_packets() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // Build an ICMP packet (protocol=1) with TTL=1.
        let mut pkt = Vec::new();
        // Ethernet header
        pkt.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00);
        let total_len: u16 = 20 + 8; // IP header + 8 bytes ICMP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(1); // TTL = 1
        pkt.push(1); // protocol = ICMP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[192, 168, 1, 100]); // src
        pkt.extend_from_slice(&[8, 8, 8, 8]); // dst

        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // ICMP Echo Request (8 bytes)
        pkt.push(8); // type: Echo Request
        pkt.push(0); // code: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // ID + seq

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: pkt,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3TtlExpired);
                assert!(
                    icmp_reply.is_none(),
                    "should NOT generate ICMP for ICMP packets (loop prevention)"
                );
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    #[test]
    fn parse_error_no_icmp() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        let raw_pkt = RawPacket {
            ingress_iface: "eth0".to_string(),
            data: vec![0x00; 5],
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::ParseError);
                assert!(icmp_reply.is_none(), "no ICMP for parse errors");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    #[test]
    fn firewall_drop_no_icmp() {
        let l3 = make_l3_engine();
        let fw = make_fw_drop_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        let data = make_ipv4_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::FirewallDrop);
                assert!(icmp_reply.is_none(), "no ICMP for firewall drops");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    #[test]
    fn not_ipv4_no_icmp() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();

        // ARP packet.
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[0x08, 0x06]); // ARP
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.push(0x06);
        data.push(0x04);
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[192, 168, 1, 1]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[192, 168, 1, 2]);

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let mut l2 = make_l2_engine_empty();
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, icmp_reply } => {
                assert_eq!(reason, DropReason::L3NotIpv4);
                assert!(icmp_reply.is_none(), "no ICMP for non-IPv4");
            }
            other => panic!("expected Drop, got {:?}", other),
        }
    }

    // ── L2 pipeline integration tests ──────────────────────────────

    /// Helper: build an L2 engine with a bridge domain containing
    /// eth0, eth1, eth2.
    fn make_l2_engine_bridged() -> L2Engine {
        L2Engine::from_config(&L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            arp_hold_queue_per_ip: 3,
            arp_hold_queue_max: 1024,
            bridge_domains: vec![BridgeDomain {
                name: "br0".to_string(),
                members: vec!["eth0".to_string(), "eth1".to_string(), "eth2".to_string()],
            }],
        })
    }

    /// Helper: build an L3 engine that knows about eth0/eth1/eth2
    /// so that local IP checks work in the L2 pipeline tests.
    fn make_l3_engine_with_bridge_ifaces() -> L3Engine {
        let routing = RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "0.0.0.0/0".to_string(),
                next_hop: "10.0.0.1".to_string(),
                out_if: "wan0".to_string(),
                metric: 100,
            }],
            ipv6_static_routes: vec![],
            ospf: None,
            bgp: None,
        };
        let ifaces = vec![
            InterfaceConfig {
                name: "eth0".to_string(),
                port_id: 0,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:00:01".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "eth1".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:00:02".to_string(),
                ipv4_addrs: vec![],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "eth2".to_string(),
                port_id: 2,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:00:03".to_string(),
                ipv4_addrs: vec![],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "wan0".to_string(),
                port_id: 3,
                role: InterfaceRole::Wan,
                admin_up: true,
                mtu: 1500,
                mac: "02:00:00:00:10:01".to_string(),
                ipv4_addrs: vec!["10.0.0.2/24".to_string()],
                ipv6_addrs: vec![],
                zone: InterfaceZone::Wan,
                l2_domain: "bd-wan".to_string(),
                linux_if: None,
            },
        ];
        L3Engine::from_config(&routing, &ifaces).unwrap()
    }

    const MAC_HOST_A: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
    const MAC_HOST_B: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02];
    const MAC_BROADCAST: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    /// Build a raw Ethernet + IPv4 + UDP packet with specified MACs and IPs.
    fn make_l2_raw_packet(
        ingress_iface: &str,
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
    ) -> RawPacket {
        RawPacket {
            ingress_iface: ingress_iface.to_string(),
            data: make_ipv4_packet(src_mac, dst_mac, src_ip, dst_ip, 64),
        }
    }

    #[test]
    fn l2_forward_known_unicast() {
        // Pre-learn MAC_HOST_B on eth1, then send a packet from eth0
        // to MAC_HOST_B -> should L2 forward to eth1.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        // Step 1: Learn MAC_HOST_B on eth1.
        let learn_pkt = make_l2_raw_packet(
            "eth1",
            MAC_HOST_B,
            MAC_HOST_A,
            [192, 168, 1, 50],
            [192, 168, 1, 60],
        );
        let _ = process_packet(&learn_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        // Step 2: Send from MAC_HOST_A on eth0 to MAC_HOST_B -> unicast to eth1.
        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 50],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "eth1");
            }
            other => panic!("expected Forward to eth1, got {:?}", other),
        }
    }

    #[test]
    fn l2_flood_unknown_mac() {
        // Send to an unknown MAC on eth0 -> should flood to eth1, eth2.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 50],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        match result {
            PipelineResult::Flood { egress_ifaces } => {
                assert!(
                    !egress_ifaces.contains(&"eth0".to_string()),
                    "must not include ingress"
                );
                assert!(egress_ifaces.contains(&"eth1".to_string()));
                assert!(egress_ifaces.contains(&"eth2".to_string()));
                assert_eq!(egress_ifaces.len(), 2);
            }
            other => panic!("expected Flood, got {:?}", other),
        }
    }

    #[test]
    fn l2_broadcast_floods() {
        // Broadcast MAC should always flood.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_BROADCAST,
            [192, 168, 1, 60],
            [192, 168, 1, 255],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        match result {
            PipelineResult::Flood { egress_ifaces } => {
                assert!(
                    !egress_ifaces.contains(&"eth0".to_string()),
                    "must not include ingress"
                );
                assert!(egress_ifaces.contains(&"eth1".to_string()));
                assert!(egress_ifaces.contains(&"eth2".to_string()));
                assert_eq!(egress_ifaces.len(), 2);
            }
            other => panic!("expected Flood for broadcast, got {:?}", other),
        }
    }

    #[test]
    fn l2_learning_source_mac() {
        // After processing a packet from eth0 with MAC_HOST_A,
        // MAC_HOST_A should be learned on eth0. A subsequent packet
        // to MAC_HOST_A from eth1 should unicast to eth0.
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        // Step 1: MAC_HOST_A arrives on eth0 (triggers learning).
        let learn_pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 50],
        );
        let _ = process_packet(&learn_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        // Step 2: Send to MAC_HOST_A from eth1 -> should unicast to eth0.
        let pkt = make_l2_raw_packet(
            "eth1",
            MAC_HOST_B,
            MAC_HOST_A,
            [192, 168, 1, 50],
            [192, 168, 1, 60],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        match result {
            PipelineResult::Forward { egress_iface, .. } => {
                assert_eq!(egress_iface, "eth0");
            }
            other => panic!("expected Forward to eth0, got {:?}", other),
        }
    }

    #[test]
    fn l2_plus_l3_local_ip_goes_to_l3() {
        // A packet in a bridge domain but destined for the router's
        // own IP (192.168.1.1) should bypass L2 forwarding and be
        // handed to L3 (resulting in Consumed / LocalDelivery).
        let mut l2 = make_l2_engine_bridged();
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        let pkt = make_l2_raw_packet(
            "eth0",
            MAC_HOST_A,
            MAC_HOST_B,
            [192, 168, 1, 60],
            [192, 168, 1, 1],
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        // The packet's dst IP (192.168.1.1) is a local IP on eth0,
        // so L3 should handle it as LocalDelivery -> Consumed.
        assert!(
            matches!(result, PipelineResult::Consumed),
            "expected Consumed for local IP, got {:?}",
            result
        );
    }

    #[test]
    fn l2_not_in_bridge_domain_goes_to_l3() {
        // An interface NOT in any bridge domain should skip L2 and
        // go directly to L3 routing.
        let mut l2 = make_l2_engine_bridged(); // br0: eth0, eth1, eth2
        let l3 = make_l3_engine_with_bridge_ifaces();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&[]);
        let im = std::collections::HashMap::new();

        // wan0 is NOT in br0, so it skips L2 entirely.
        let pkt = make_l2_raw_packet(
            "wan0",
            [0xAA; 6],
            [0xBB; 6],
            [10, 0, 0, 5],
            [192, 168, 1, 1], // local IP -> Consumed
        );
        let result = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        assert!(
            matches!(result, PipelineResult::Consumed),
            "expected Consumed (L3 local delivery), got {:?}",
            result
        );
    }

    // ── Conntrack integration tests ─────────────────────────────────

    /// Build a valid Ethernet + IPv4 + TCP packet with specified flags.
    fn make_tcp_packet(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        tcp_flags: u8,
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header (20 bytes)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 20; // IP header + TCP header
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(ttl);
        pkt.push(6); // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // Compute IPv4 checksum.
        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // TCP header (20 bytes minimum)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        pkt.push(0x50); // data offset = 5 (20 bytes), reserved bits
        pkt.push(tcp_flags);
        pkt.extend_from_slice(&[0xFF, 0xFF]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer
        pkt
    }

    #[test]
    fn conntrack_creates_session_for_new_flow() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        assert_eq!(ct.session_count(), 0);

        // Send a UDP packet from LAN to WAN.
        let data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert!(matches!(result, PipelineResult::Forward { .. }));

        // A conntrack session should have been created.
        assert_eq!(ct.session_count(), 1);
    }

    #[test]
    fn conntrack_reuses_session_for_same_flow() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);

        // Send the same packet twice.
        let pkt1 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: data.clone(),
        };
        let _ = process_packet(&pkt1, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert_eq!(ct.session_count(), 1);

        let pkt2 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };
        let _ = process_packet(&pkt2, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        // Should still be 1 session (reused).
        assert_eq!(ct.session_count(), 1);
    }

    #[test]
    fn conntrack_matches_reverse_direction() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // SYN: LAN 192.168.1.100:49152 -> WAN 8.8.8.8:80
        let syn_data = make_tcp_packet(
            [0xAA; 6],
            [0xBB; 6],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            49152,
            80,
            0x02, // SYN
            64,
        );
        let syn_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: syn_data,
        };
        let _ = process_packet(&syn_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert_eq!(ct.session_count(), 1);

        // SYN-ACK: WAN 8.8.8.8:80 -> LAN 192.168.1.100:49152
        // This is the reverse direction.
        let synack_data = make_tcp_packet(
            [0xBB; 6],
            [0xAA; 6],
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            80,
            49152,
            0x12, // SYN+ACK
            64,
        );
        let synack_pkt = RawPacket {
            ingress_iface: "wan0".to_string(),
            data: synack_data,
        };
        let _ = process_packet(&synack_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);

        // Should still be 1 session (reverse matched the existing one).
        assert_eq!(ct.session_count(), 1);
    }

    #[test]
    fn conntrack_tcp_lifecycle_syn_established_fin() {
        use crate::conntrack::session::{SessionKey, SessionProto, SessionState, TcpState};

        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let src_ip = [192, 168, 1, 100];
        let dst_ip = [8, 8, 8, 8];
        let src_port = 49152u16;
        let dst_port = 80u16;

        // Step 1: SYN
        let syn = make_tcp_packet(
            [0xAA; 6], [0xBB; 6], src_ip, dst_ip, src_port, dst_port, 0x02, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "lan0".to_string(),
                data: syn,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
        );

        let key = SessionKey {
            src_ip,
            dst_ip,
            proto: SessionProto::Tcp { src_port, dst_port },
        };
        let session = ct.lookup(&key).expect("session should exist after SYN");
        assert_eq!(session.state, SessionState::Tcp(TcpState::SynSent));

        // Step 2: SYN-ACK (reverse direction triggers ACK flag -> Established)
        let synack = make_tcp_packet(
            [0xBB; 6], [0xAA; 6], dst_ip, src_ip, dst_port, src_port, 0x12, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "wan0".to_string(),
                data: synack,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
        );

        let session = ct
            .lookup(&key)
            .expect("session should still exist after SYN-ACK");
        assert_eq!(session.state, SessionState::Tcp(TcpState::Established));

        // Step 3: FIN (forward direction)
        let fin = make_tcp_packet(
            [0xAA; 6], [0xBB; 6], src_ip, dst_ip, src_port, dst_port, 0x01, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "lan0".to_string(),
                data: fin,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
        );

        let session = ct
            .lookup(&key)
            .expect("session should still exist after FIN");
        assert_eq!(session.state, SessionState::Tcp(TcpState::FinWait));

        // Step 4: FIN (reverse direction) -> Closed
        let fin_rev = make_tcp_packet(
            [0xBB; 6], [0xAA; 6], dst_ip, src_ip, dst_port, src_port, 0x01, 64,
        );
        let _ = process_packet(
            &RawPacket {
                ingress_iface: "wan0".to_string(),
                data: fin_rev,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
        );

        let session = ct
            .lookup(&key)
            .expect("session should still exist after both FINs");
        assert_eq!(session.state, SessionState::Tcp(TcpState::Closed));
    }

    #[test]
    fn conntrack_table_full_drops_packet() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        // Create a conntrack with max 1 session.
        let mut ct = ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1,
            tcp_established_timeout_sec: 7200,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 300,
            icmp_timeout_sec: 30,
        });
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // First packet fills the table.
        let data1 = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let pkt1 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: data1,
        };
        let result1 = process_packet(&pkt1, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert!(matches!(result1, PipelineResult::Forward { .. }));
        assert_eq!(ct.session_count(), 1);

        // Second packet from a different flow should be dropped (table full).
        let data2 = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 101], [8, 8, 8, 8], 64);
        let pkt2 = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: data2,
        };
        let result2 = process_packet(&pkt2, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert!(
            matches!(
                result2,
                PipelineResult::Drop {
                    reason: DropReason::ConntrackTableFull,
                    ..
                }
            ),
            "expected Drop(ConntrackTableFull) when table is full, got {:?}",
            result2
        );
    }

    #[test]
    fn conntrack_gc_removes_expired_sessions() {
        use std::thread;
        use std::time::Duration;

        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        // Conntrack with 0-second UDP timeout so sessions expire immediately.
        let mut ct = ConntrackEngine::new(ConntrackConfig {
            max_sessions: 1000,
            tcp_established_timeout_sec: 3600,
            tcp_transitory_timeout_sec: 120,
            udp_timeout_sec: 0,
            icmp_timeout_sec: 30,
        });
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // Create a UDP session.
        let data = make_ipv4_packet([0xAA; 6], [0xBB; 6], [192, 168, 1, 100], [8, 8, 8, 8], 64);
        let pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };
        let _ = process_packet(&pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert_eq!(ct.session_count(), 1);

        // Wait for session to expire.
        thread::sleep(Duration::from_millis(10));

        // Run GC.
        let expired = ct.gc();
        assert_eq!(expired, 1);
        assert_eq!(ct.session_count(), 0);
    }

    #[test]
    fn conntrack_fw_allow_established_integration() {
        // Integration test: firewall with allow_established_related and
        // default_forward=drop. A new outbound flow creates a conntrack
        // session, then the reverse (return) traffic should be accepted
        // because the session exists.
        use ruster_config::model::{Chain, ConnState, FirewallRule, RuleAction, RuleProto};

        let l3 = make_l3_engine();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // FW: allow LAN->WAN new, allow established/related, default forward=drop.
        let fw = FirewallEngine::from_config(&FirewallConfig {
            enabled: true,
            default_input: DefaultPolicy::Drop,
            default_forward: DefaultPolicy::Drop,
            default_output: DefaultPolicy::Accept,
            allow_established_related: true,
            rules: vec![FirewallRule {
                name: "allow-lan-to-wan".to_string(),
                chain: Chain::Forward,
                action: RuleAction::Accept,
                proto: RuleProto::Any,
                src_zone: FirewallZone::Lan,
                dst_zone: FirewallZone::Wan,
                state: vec![ConnState::New],
            }],
        });

        // Step 1: Outbound SYN from LAN -> WAN (should be accepted by rule).
        let syn = make_tcp_packet(
            [0xAA; 6],
            [0xBB; 6],
            [192, 168, 1, 100],
            [8, 8, 8, 8],
            49152,
            80,
            0x02,
            64,
        );
        let result1 = process_packet(
            &RawPacket {
                ingress_iface: "lan0".to_string(),
                data: syn,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
        );
        assert!(
            matches!(result1, PipelineResult::Forward { .. }),
            "outbound SYN should be forwarded, got {:?}",
            result1
        );
        assert_eq!(ct.session_count(), 1, "session should be created");

        // Step 2: Return SYN-ACK from WAN -> LAN (reverse direction).
        // Without conntrack, this would be dropped by default_forward=drop
        // because there's no rule for WAN->LAN new traffic.
        // With conntrack, the reverse key matches the existing session,
        // so FwContext::from_packet sees is_established=true ->
        // allow_established_related accepts it.
        let synack = make_tcp_packet(
            [0xBB; 6],
            [0xAA; 6],
            [8, 8, 8, 8],
            [192, 168, 1, 100],
            80,
            49152,
            0x12,
            64,
        );
        let result2 = process_packet(
            &RawPacket {
                ingress_iface: "wan0".to_string(),
                data: synack,
            },
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
        );
        assert!(
            matches!(result2, PipelineResult::Forward { .. }),
            "return SYN-ACK should be forwarded (established), got {:?}",
            result2
        );
    }

    #[test]
    fn conntrack_untracked_arp_does_not_create_session() {
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // ARP packet -> not trackable -> no session created.
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[0x08, 0x06]); // ARP
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.push(0x06);
        data.push(0x04);
        data.extend_from_slice(&[0x00, 0x01]);
        data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data.extend_from_slice(&[192, 168, 1, 1]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[192, 168, 1, 2]);

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let _ = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        assert_eq!(
            ct.session_count(),
            0,
            "ARP should not create a conntrack session"
        );
    }

    // ── IPv6 pipeline tests ──────────────────────────────────────────

    use crate::nd::NdEngine;
    use crate::routing::ipv6_table::Ipv6RouteTable;
    use ruster_config::model::Ipv6StaticRoute;

    fn make_ipv6_interfaces() -> Vec<InterfaceConfig> {
        vec![
            InterfaceConfig {
                name: "wan0".to_string(),
                port_id: 0,
                role: InterfaceRole::Wan,
                admin_up: true,
                mtu: 1500,
                mac: "00:11:22:33:44:55".to_string(),
                ipv4_addrs: vec!["10.0.0.2/24".to_string()],
                ipv6_addrs: vec!["2001:db8::2/64".to_string()],
                zone: InterfaceZone::Wan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
            InterfaceConfig {
                name: "lan0".to_string(),
                port_id: 1,
                role: InterfaceRole::Lan,
                admin_up: true,
                mtu: 1500,
                mac: "00:AA:BB:CC:DD:EE".to_string(),
                ipv4_addrs: vec!["192.168.1.1/24".to_string()],
                ipv6_addrs: vec!["2001:db8:1::1/64".to_string()],
                zone: InterfaceZone::Lan,
                l2_domain: "br0".to_string(),
                linux_if: None,
            },
        ]
    }

    fn make_ipv6_routing_config() -> RoutingConfig {
        RoutingConfig {
            ipv4_static_routes: vec![StaticRoute {
                prefix: "0.0.0.0/0".to_string(),
                next_hop: "10.0.0.1".to_string(),
                out_if: "wan0".to_string(),
                metric: 100,
            }],
            ipv6_static_routes: vec![
                Ipv6StaticRoute {
                    prefix: "::/0".to_string(),
                    next_hop: "2001:db8::1".to_string(),
                    out_if: "wan0".to_string(),
                    metric: 100,
                },
                Ipv6StaticRoute {
                    prefix: "2001:db8:1::/48".to_string(),
                    next_hop: "::".to_string(),
                    out_if: "lan0".to_string(),
                    metric: 10,
                },
            ],
            ospf: None,
            bgp: None,
        }
    }

    fn make_nd_engine() -> NdEngine {
        let l2_config = L2Config {
            mac_table_max_entries: 1024,
            mac_aging_sec: 300,
            arp_table_max_entries: 256,
            arp_timeout_sec: 120,
            arp_hold_queue_per_ip: 3,
            arp_hold_queue_max: 1024,
            bridge_domains: vec![],
        };
        NdEngine::from_config(&l2_config, &make_ipv6_interfaces())
    }

    fn make_ipv6_route_table() -> Ipv6RouteTable {
        Ipv6RouteTable::from_config(&make_ipv6_routing_config()).unwrap()
    }

    /// Build a valid Ethernet + IPv6 + UDP packet.
    fn make_ipv6_packet(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ipv6: [u8; 16],
        dst_ipv6: [u8; 16],
        hop_limit: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType IPv6

        // IPv6 header (40 bytes)
        // Version=6, TC=0, FL=0
        pkt.push(0x60);
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        // Payload Length = 8 (UDP header only)
        pkt.extend_from_slice(&8u16.to_be_bytes());
        // Next Header: UDP (17)
        pkt.push(17);
        // Hop Limit
        pkt.push(hop_limit);
        // Source Address
        pkt.extend_from_slice(&src_ipv6);
        // Destination Address
        pkt.extend_from_slice(&dst_ipv6);

        // Minimal UDP header (8 bytes)
        pkt.extend_from_slice(&[0x00, 0x50]); // src port: 80
        pkt.extend_from_slice(&[0x00, 0x51]); // dst port: 81
        pkt.extend_from_slice(&[0x00, 0x08]); // length: 8
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum: 0
        pkt
    }

    #[test]
    fn ipv6_forward_via_default_route() {
        let l3 =
            L3Engine::from_config(&make_ipv6_routing_config(), &make_ipv6_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&make_ipv6_interfaces());
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let mut nd = make_nd_engine();
        let ipv6_routes = make_ipv6_route_table();

        // 2001:db8:2::100 should match the default route -> wan0
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let data = make_ipv6_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src,
            dst,
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet_v6(
            &raw_pkt,
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
            Some(&mut nd),
            Some(&ipv6_routes),
            None,
        );
        match result {
            PipelineResult::ForwardV6 {
                egress_iface,
                new_hop_limit,
                ..
            } => {
                assert_eq!(egress_iface, "wan0");
                assert_eq!(new_hop_limit, 63);
            }
            other => panic!("expected ForwardV6, got {:?}", other),
        }
    }

    #[test]
    fn ipv6_local_delivery() {
        let l3 =
            L3Engine::from_config(&make_ipv6_routing_config(), &make_ipv6_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&make_ipv6_interfaces());
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let mut nd = make_nd_engine();
        let ipv6_routes = make_ipv6_route_table();

        // Destination is our local IPv6 (2001:db8:1::1 on lan0).
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let data = make_ipv6_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src,
            dst,
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet_v6(
            &raw_pkt,
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
            Some(&mut nd),
            Some(&ipv6_routes),
            None,
        );
        assert!(
            matches!(result, PipelineResult::Consumed),
            "expected Consumed for local IPv6, got {:?}",
            result
        );
    }

    #[test]
    fn ipv6_hop_limit_expired() {
        let l3 =
            L3Engine::from_config(&make_ipv6_routing_config(), &make_ipv6_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&make_ipv6_interfaces());
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let mut nd = make_nd_engine();
        let ipv6_routes = make_ipv6_route_table();

        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        // Hop limit = 1 -> should be dropped.
        let data = make_ipv6_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src,
            dst,
            1,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet_v6(
            &raw_pkt,
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
            Some(&mut nd),
            Some(&ipv6_routes),
            None,
        );
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3HopLimitExpired);
            }
            other => panic!("expected Drop(L3HopLimitExpired), got {:?}", other),
        }
    }

    #[test]
    fn ipv6_no_route() {
        let l3 =
            L3Engine::from_config(&make_ipv6_routing_config(), &make_ipv6_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&make_ipv6_interfaces());
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let mut nd = make_nd_engine();
        // Route table with NO default route -- only a specific /48.
        let routing_no_default = RoutingConfig {
            ipv4_static_routes: vec![],
            ipv6_static_routes: vec![Ipv6StaticRoute {
                prefix: "2001:db8:1::/48".to_string(),
                next_hop: "::".to_string(),
                out_if: "lan0".to_string(),
                metric: 10,
            }],
            ospf: None,
            bgp: None,
        };
        let ipv6_routes = Ipv6RouteTable::from_config(&routing_no_default).unwrap();

        // Destination 2001:db8:2::1 has no matching route.
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let data = make_ipv6_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            src,
            dst,
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet_v6(
            &raw_pkt,
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
            Some(&mut nd),
            Some(&ipv6_routes),
            None,
        );
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3NoRoute);
            }
            other => panic!("expected Drop(L3NoRoute), got {:?}", other),
        }
    }

    #[test]
    fn ipv6_nd_consumed() {
        let l3 =
            L3Engine::from_config(&make_ipv6_routing_config(), &make_ipv6_interfaces()).unwrap();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = ZoneResolver::from_config(&make_ipv6_interfaces());
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();
        let mut nd = make_nd_engine();
        let ipv6_routes = make_ipv6_route_table();

        // Build a Neighbor Solicitation packet.
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // dst: solicited-node multicast
        pkt.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // src
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6

        // IPv6 header (40 bytes)
        pkt.push(0x60); // Version=6
        pkt.push(0x00);
        pkt.push(0x00);
        pkt.push(0x00);
        // Payload Length = 24 (NS without options)
        pkt.extend_from_slice(&24u16.to_be_bytes());
        // Next Header: ICMPv6 (58)
        pkt.push(58);
        // Hop Limit: 255
        pkt.push(255);
        // Source: 2001:db8:1::64
        let src_ip = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
        ];
        pkt.extend_from_slice(&src_ip);
        // Destination: ff02::1:ff00:1 (solicited-node multicast)
        let dst_ip = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0, 0, 0x01,
        ];
        pkt.extend_from_slice(&dst_ip);

        // ICMPv6 NS (24 bytes)
        pkt.push(135); // Type: NS
        pkt.push(0); // Code: 0
        pkt.extend_from_slice(&[0x00, 0x00]); // Checksum (simplified)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved
                                                          // Target: 2001:db8:1::1 (our address)
        let target = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        pkt.extend_from_slice(&target);

        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data: pkt,
        };

        let result = process_packet_v6(
            &raw_pkt,
            &mut l2,
            &l3,
            &fw,
            &mut ct,
            &mut nat,
            &zr,
            &im,
            Some(&mut nd),
            Some(&ipv6_routes),
            None,
        );
        assert!(
            matches!(
                result,
                PipelineResult::NdReply { .. } | PipelineResult::Consumed
            ),
            "expected NdReply or Consumed for ND packet, got {:?}",
            result
        );
    }

    #[test]
    fn ipv6_without_engines_falls_through_to_not_ipv4() {
        // When IPv6 engines are None, IPv6 packets are handled by
        // the IPv4 L3 engine which returns Drop(NotIpv4).
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_disabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        let data = make_ipv6_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            src,
            dst,
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        // Call with no IPv6 engines.
        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Drop { reason, .. } => {
                assert_eq!(reason, DropReason::L3NotIpv4);
            }
            other => panic!("expected Drop(L3NotIpv4), got {:?}", other),
        }
    }

    // ── NAT pipeline integration tests ───────────────────────────────

    /// Build a NAT engine with NAPT enabled and a UDP port-forward rule:
    /// external port 8080 -> 192.168.1.50:80.
    fn make_nat_with_port_forward() -> NatEngine {
        use ruster_config::model::PortForward;
        NatEngine::from_config(
            &NatConfig {
                enabled: true,
                mode: NatMode::Napt44,
                external_if: "wan0".to_string(),
                hairpin: false,
                session_table_max_entries: 1000,
                tcp_established_timeout_sec: 7200,
                tcp_transitory_timeout_sec: 120,
                udp_timeout_sec: 300,
                icmp_timeout_sec: 30,
                port_forwards: vec![PortForward {
                    name: "web-server".to_string(),
                    proto: ruster_config::model::PortForwardProto::Udp,
                    external_port: 8080,
                    internal_addr: "192.168.1.50".to_string(),
                    internal_port: 80,
                }],
            },
            &make_interfaces(),
        )
    }

    /// Build a NAT engine with NAPT enabled (outbound SNAT) but no port forwards.
    fn make_nat_enabled() -> NatEngine {
        NatEngine::from_config(
            &NatConfig {
                enabled: true,
                mode: NatMode::Napt44,
                external_if: "wan0".to_string(),
                hairpin: false,
                session_table_max_entries: 1000,
                tcp_established_timeout_sec: 7200,
                tcp_transitory_timeout_sec: 120,
                udp_timeout_sec: 300,
                icmp_timeout_sec: 30,
                port_forwards: vec![],
            },
            &make_interfaces(),
        )
    }

    /// Build a valid Ethernet + IPv4 + UDP packet with configurable ports.
    fn make_ipv4_udp_packet(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        ttl: u8,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&dst_mac);
        pkt.extend_from_slice(&src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        // IPv4 header (20 bytes minimum)
        let ipv4_start = pkt.len();
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 20 + 8; // IP header + 8 bytes UDP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        pkt.push(ttl);
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // Compute IPv4 checksum
        set_ipv4_checksum(&mut pkt[ipv4_start..ipv4_start + 20]);

        // UDP header (8 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x08]); // length: 8
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum: 0
        pkt
    }

    #[test]
    fn dnat_port_forward_routes_to_internal_server() {
        // DNAT port forward: WAN packet with dst=router WAN IP (10.0.0.2)
        // and dst_port=8080 should be DNAT'd to 192.168.1.50:80, then
        // routed to lan0 (192.168.1.0/24) instead of returning LocalDelivery.
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_with_port_forward();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // Packet from external host 203.0.113.10:54321 ->
        // router's WAN IP 10.0.0.2:8080, entering via wan0.
        let data = make_ipv4_udp_packet(
            [0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01], // external host MAC
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], // router WAN MAC
            [203, 0, 113, 10],                    // external src IP
            [10, 0, 0, 2],                        // router WAN IP (dst)
            54321,                                // src port
            8080,                                 // dst port (matches port forward)
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "wan0".to_string(),
            data,
        };

        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Forward {
                egress_iface, nat, ..
            } => {
                // DNAT should route the packet to the LAN (192.168.1.50 is on
                // the 192.168.1.0/24 subnet -> out via lan0).
                assert_eq!(egress_iface, "lan0");
                // The NAT result should carry the DNAT translation.
                assert_eq!(
                    nat,
                    NatResult::Dnat {
                        new_dst_ip: [192, 168, 1, 50],
                        new_dst_port: 80,
                    }
                );
            }
            other => panic!(
                "expected Forward with DNAT to lan0, got {:?}. \
                 Without the DNAT fix, this would be Consumed (LocalDelivery) \
                 because the original dst_ip is the router's own WAN IP.",
                other
            ),
        }
    }

    #[test]
    fn snat_outbound_through_pipeline() {
        // SNAT outbound: LAN packet from 192.168.1.100 -> 8.8.8.8 should be
        // forwarded via wan0 with SNAT to the router's WAN IP (10.0.0.2).
        let l3 = make_l3_engine();
        let fw = make_fw_accept_all();
        let mut ct = make_conntrack();
        let mut nat = make_nat_enabled();
        let zr = make_zone_resolver();
        let im = std::collections::HashMap::new();
        let mut l2 = make_l2_engine_empty();

        // Packet from LAN host 192.168.1.100:49152 -> 8.8.8.8:53, entering
        // via lan0.
        let data = make_ipv4_udp_packet(
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // LAN host MAC
            [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE], // router LAN MAC
            [192, 168, 1, 100],                   // LAN host IP
            [8, 8, 8, 8],                         // external dst IP
            49152,                                // src port
            53,                                   // dst port (DNS)
            64,
        );
        let raw_pkt = RawPacket {
            ingress_iface: "lan0".to_string(),
            data,
        };

        let result = process_packet(&raw_pkt, &mut l2, &l3, &fw, &mut ct, &mut nat, &zr, &im);
        match result {
            PipelineResult::Forward {
                egress_iface, nat, ..
            } => {
                assert_eq!(egress_iface, "wan0");
                // SNAT should translate src to the router's WAN IP.
                match nat {
                    NatResult::Snat {
                        new_src_ip,
                        new_src_port,
                    } => {
                        assert_eq!(new_src_ip, [10, 0, 0, 2]);
                        // Port should be in the ephemeral range (>= 10000).
                        assert!(
                            new_src_port >= 10000,
                            "SNAT port should be ephemeral, got {}",
                            new_src_port
                        );
                    }
                    other => panic!("expected Snat, got {:?}", other),
                }
            }
            other => panic!("expected Forward with SNAT to wan0, got {:?}", other),
        }
    }
}

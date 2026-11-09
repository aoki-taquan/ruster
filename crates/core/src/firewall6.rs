//! The forward firewall for IPv6: what of a forwarded IPv6 packet the firewall
//! looks at, and the decision for it. The rules and the state table are the ones
//! IPv4 uses ([`crate::firewall`]).
//!
//! # Standards
//!
//! - RFC 8200 section 4: the extension headers (Hop-by-Hop Options, Routing,
//!   Destination Options, Fragment) are stepped over to find the upper-layer
//!   header.
//! - RFC 4890 section 4.3: ICMPv6 errors (Destination Unreachable, Packet Too Big,
//!   Time Exceeded, Parameter Problem) about a flow the firewall lets through pass
//!   with it; Packet Too Big is needed for path MTU discovery (RFC 8201). Echo
//!   Request and Reply are a query flow, as ICMPv4's.
//! - RFC 6092 (Simple Security in IPv6 CPE) as the model: state for outgoing flows,
//!   replies and related errors pass, what no rule accepts is dropped, except
//!   what the filtering lets reach an inside endpoint (REC-11, REC-17, REC-33; see
//!   [`crate::firewall`]).
//!
//! Deviations:
//!
//! - A fragment that is not the first is dropped (IPv4 tracks them; IPv6 does not
//!   yet). At most eight extension headers are stepped over; AH, ESP and "No Next
//!   Header" are not looked into and are dropped.
//! - TCP and UDP checksums, port 0 and a TCP data offset past the payload are not
//!   checked here (the destination does).
//! - With the firewall on, a packet from the default VRF with no route is dropped
//!   without a Destination Unreachable (IPv4 asks the rules whether it would pass).
//! - ICMPv6 other than Echo and the four errors is dropped (ND is not forwarded).
//! - A Routing header of type 0 is stepped over like the others and its packet
//!   forwarded (RFC 6092 REC-4 asks a CE to drop it; RFC 5095 forbids only
//!   processing it at the destination, which the router is not).

use crate::firewall::{FirewallAddress, FirewallPacket, FIREWALL_ICMP_REPLY};
use crate::{
    DropReason, FirewallAuditBuffer, FirewallConfig, FirewallProtocol, FirewallRuntime, IfId,
};

const ETHERNET: usize = 14;
const IPV6_HEADER: usize = 40;
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DESTINATION_OPTIONS: u8 = 60;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMPV6: u8 = 58;
const MAX_EXTENSION_HEADERS: usize = 8;
const ECHO_REQUEST: u8 = 128;
const ECHO_REPLY: u8 = 129;

/// What follows the extension headers of an IPv6 packet at `ip` in `frame`.
struct Upper {
    protocol: u8,
    /// Where the upper-layer header starts.
    offset: usize,
    /// The end of the IPv6 payload.
    end: usize,
}

/// Steps over the extension headers of the IPv6 packet at `ip`. `Err` for what the
/// firewall does not look into.
fn upper(frame: &[u8], ip: usize) -> Result<Upper, DropReason> {
    let header = frame
        .get(ip..ip + IPV6_HEADER)
        .ok_or(DropReason::Ipv6HeaderTruncated)?;
    let payload = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let end = ip + IPV6_HEADER + payload;
    if end > frame.len() {
        return Err(DropReason::Ipv6PayloadLengthExceedsPacket);
    }
    walk(frame, ip, end)
}

/// Steps over the extension headers of the IPv6 header at `ip`, reading nothing
/// at or after `end`.
fn walk(frame: &[u8], ip: usize, end: usize) -> Result<Upper, DropReason> {
    let header = frame
        .get(ip..ip + IPV6_HEADER)
        .filter(|_| ip + IPV6_HEADER <= end)
        .ok_or(DropReason::FirewallUnsupportedProtocol)?;
    let mut next = header[6];
    let mut offset = ip + IPV6_HEADER;
    // Up to MAX_EXTENSION_HEADERS headers, then the upper-layer one.
    for _ in 0..=MAX_EXTENSION_HEADERS {
        match next {
            HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS => {
                let ext = frame
                    .get(offset..offset + 2)
                    .filter(|_| offset + 2 <= end)
                    .ok_or(DropReason::FirewallUnsupportedProtocol)?;
                next = ext[0];
                offset += (usize::from(ext[1]) + 1) * 8;
            }
            FRAGMENT => {
                let ext = frame
                    .get(offset..offset + 8)
                    .filter(|_| offset + 8 <= end)
                    .ok_or(DropReason::FirewallUnsupportedProtocol)?;
                // Only the first fragment has the upper-layer header.
                if u16::from_be_bytes([ext[2], ext[3]]) >> 3 != 0 {
                    return Err(DropReason::FirewallFragmentUnsupported);
                }
                next = ext[0];
                offset += 8;
            }
            protocol => {
                if offset > end {
                    return Err(DropReason::FirewallUnsupportedProtocol);
                }
                return Ok(Upper {
                    protocol,
                    offset,
                    end,
                });
            }
        }
    }
    Err(DropReason::FirewallUnsupportedProtocol)
}

fn address(frame: &[u8], at: usize) -> FirewallAddress {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&frame[at..at + 16]);
    FirewallAddress::V6(bytes)
}

/// The firewall's view of a TCP, UDP or ICMPv6 Echo packet at `ip`: the protocol,
/// its ports (an Echo's are the identifier and type, as for ICMPv4) and flags.
/// `Ok(None)` for an ICMPv6 error, which is RELATED or nothing.
fn transport(
    frame: &[u8],
    upper: &Upper,
) -> Result<Option<(FirewallProtocol, u16, u16, u8)>, DropReason> {
    let at = upper.offset;
    let bytes = |len: usize| {
        frame
            .get(at..at + len)
            .filter(|_| at + len <= upper.end)
            .ok_or(DropReason::FirewallUnsupportedProtocol)
    };
    let port = |b: &[u8], i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
    match upper.protocol {
        TCP => {
            let tcp = bytes(20)?;
            if tcp[12] >> 4 < 5 {
                return Err(DropReason::FirewallTcpDataOffsetTooSmall);
            }
            Ok(Some((
                FirewallProtocol::Tcp,
                port(tcp, 0),
                port(tcp, 2),
                tcp[13],
            )))
        }
        UDP => {
            let udp = bytes(8)?;
            Ok(Some((FirewallProtocol::Udp, port(udp, 0), port(udp, 2), 0)))
        }
        ICMPV6 => {
            let icmp = bytes(8)?;
            let identifier = port(icmp, 4);
            match icmp[0] {
                // As ICMPv4's: a request is (identifier, type), its reply the exact
                // reverse.
                ECHO_REQUEST => Ok(Some((
                    FirewallProtocol::Icmpv6,
                    identifier,
                    u16::from(ECHO_REQUEST),
                    0,
                ))),
                ECHO_REPLY => Ok(Some((
                    FirewallProtocol::Icmpv6,
                    u16::from(ECHO_REQUEST),
                    identifier,
                    FIREWALL_ICMP_REPLY,
                ))),
                1..=4 => Ok(None),
                _ => Err(DropReason::FirewallUnsupportedProtocol),
            }
        }
        _ => Err(DropReason::FirewallUnsupportedProtocol),
    }
}

/// Lets the forwarded IPv6 packet in `frame` (an Ethernet frame) from `ingress` to
/// `egress` through the firewall, or says why not. A new flow is written to the
/// state table at once; if a later stage (PPPoE, VLAN) cannot send the packet, the
/// flow stays, as for IPv4.
pub(crate) fn check(
    frame: &[u8],
    ingress: IfId,
    egress: IfId,
    config: &FirewallConfig<'_>,
    runtime: &mut FirewallRuntime<'_>,
    audit: &mut Option<&mut FirewallAuditBuffer<'_>>,
    now_ms: u64,
) -> Result<(), DropReason> {
    let ip = ETHERNET;
    let upper = upper(frame, ip)?;
    let source = address(frame, ip + 8);
    let destination = address(frame, ip + 24);
    match transport(frame, &upper)? {
        Some((protocol, source_port, destination_port, tcp_flags)) => {
            let packet = FirewallPacket {
                ingress,
                egress,
                source,
                destination,
                protocol,
                source_port,
                destination_port,
                tcp_flags,
            };
            let plan =
                crate::forwarding::plan_firewall_packet(packet, config, runtime, audit, now_ms)?;
            runtime
                .commit(plan)
                .map_err(|_| DropReason::FirewallStateTableFull)
        }
        None => related(frame, &upper, ingress, egress, runtime, now_ms),
    }
}

/// An ICMPv6 error passes when the packet it quotes is a flow the firewall lets
/// through: the quoted packet went the other way, from `egress` to `ingress`.
fn related(
    frame: &[u8],
    upper: &Upper,
    ingress: IfId,
    egress: IfId,
    runtime: &FirewallRuntime<'_>,
    now_ms: u64,
) -> Result<(), DropReason> {
    let unrelated = DropReason::FirewallIcmpv6Unrelated;
    let quoted = upper.offset + 8;
    if frame.get(quoted).map(|b| b >> 4) != Some(6) {
        return Err(unrelated);
    }
    // The quote may be cut short: its headers are read up to the end of this
    // packet, not by the quoted payload length.
    let inner = walk(frame, quoted, upper.end).map_err(|_| unrelated)?;
    // Only the ports are needed, and a quote may end right after them.
    let ports = |at: usize| {
        frame
            .get(at..at + 4)
            .filter(|_| at + 4 <= inner.end)
            .map(|p| {
                (
                    u16::from_be_bytes([p[0], p[1]]),
                    u16::from_be_bytes([p[2], p[3]]),
                )
            })
    };
    let (protocol, source_port, destination_port, tcp_flags) = match inner.protocol {
        TCP => {
            let (source, destination) = ports(inner.offset).ok_or(unrelated)?;
            (FirewallProtocol::Tcp, source, destination, 0)
        }
        UDP => {
            let (source, destination) = ports(inner.offset).ok_or(unrelated)?;
            (FirewallProtocol::Udp, source, destination, 0)
        }
        _ => match transport(frame, &inner) {
            Ok(Some(quoted)) => quoted,
            _ => return Err(unrelated),
        },
    };
    // An error goes to the sender of the packet it quotes (RFC 4443 2.4): one to any
    // other host is not about that flow, whatever it quotes.
    let quoted_source = address(frame, quoted + 8);
    if quoted_source != address(frame, ETHERNET + 24) {
        return Err(unrelated);
    }
    let packet = FirewallPacket {
        ingress: egress,
        egress: ingress,
        source: quoted_source,
        destination: address(frame, quoted + 24),
        protocol,
        source_port,
        destination_port,
        tcp_flags,
    };
    runtime
        .inspect_related_packet(packet, true, now_ms)
        .map(|_| ())
        .map_err(|_| unrelated)
}

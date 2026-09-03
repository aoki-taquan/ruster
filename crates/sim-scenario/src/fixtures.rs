//! Optional typed fixture inputs for scenario callers. Every frame is built
//! from typed field values (no packet-path strings); these convenience
//! constructors intentionally remain separate from the independent test
//! oracle in `tests/support`.

use ruster_core::{internet_checksum, ipv4_header_checksum};

pub const LAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const WAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
pub const WAN_NEXT_HOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 3];
pub const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];

pub const LAN_IP: [u8; 4] = [192, 0, 2, 1];
pub const HOST_IP: [u8; 4] = [192, 0, 2, 20];
pub const WAN_IP: [u8; 4] = [198, 51, 100, 10];
pub const WAN_NEXT_HOP_IP: [u8; 4] = [198, 51, 100, 1];
pub const REMOTE_IP: [u8; 4] = [203, 0, 113, 5];

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_OPER_REQUEST: u16 = 1;
const ARP_OPER_REPLY: u16 = 2;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_TCP: u8 = 6;

fn ethernet_header(dest: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(14);
    header.extend_from_slice(&dest);
    header.extend_from_slice(&src);
    header.extend_from_slice(&ethertype.to_be_bytes());
    header
}

/// Ethernet + ARP request frame, zero-padded to the 60-byte minimum.
#[must_use]
pub fn arp_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut frame = ethernet_header([0xff; 6], sender_mac, ETHERTYPE_ARP);
    frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&ARP_OPER_REQUEST.to_be_bytes());
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target_ip);
    frame.resize(60, 0);
    frame
}

/// Ethernet + ARP reply frame, zero-padded to the 60-byte minimum.
#[must_use]
pub fn arp_reply(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = ethernet_header(target_mac, sender_mac, ETHERTYPE_ARP);
    frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&ARP_OPER_REPLY.to_be_bytes());
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip);
    frame.extend_from_slice(&target_mac);
    frame.extend_from_slice(&target_ip);
    frame.resize(60, 0);
    frame
}

fn ipv4_header(
    total_length: u16,
    ttl: u8,
    protocol: u8,
    source: [u8; 4],
    destination: [u8; 4],
) -> [u8; 20] {
    let mut header = [0_u8; 20];
    header[0] = 0x45;
    header[1] = 0x00;
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[4..6].copy_from_slice(&0_u16.to_be_bytes());
    header[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    header[8] = ttl;
    header[9] = protocol;
    header[10..12].copy_from_slice(&0_u16.to_be_bytes());
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    let checksum = ipv4_header_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    header
}

fn udp_pseudo_and_segment(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_length = u16::try_from(8 + payload.len()).expect("scenario payload fits u16");
    let mut segment = Vec::with_capacity(8 + payload.len());
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&udp_length.to_be_bytes());
    segment.extend_from_slice(&0_u16.to_be_bytes());
    segment.extend_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.push(0);
    pseudo.push(IPPROTO_UDP);
    pseudo.extend_from_slice(&udp_length.to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let checksum = internet_checksum(&pseudo);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// The link-layer next hop a frame is sent to and sent from. Distinct from
/// the IPv4 source/destination: the Ethernet destination is usually the
/// router itself (or the eventual next hop on egress), not the IP packet's
/// ultimate destination host.
#[derive(Clone, Copy, Debug)]
pub struct EthernetHop {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
}

/// Ethernet + IPv4 + UDP frame from `source`/`source_port` to
/// `destination`/`destination_port`, with a correct IPv4 and UDP checksum.
#[must_use]
pub fn udp_frame(
    link: EthernetHop,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let segment =
        udp_pseudo_and_segment(source, destination, source_port, destination_port, payload);
    let total_length = u16::try_from(20 + segment.len()).expect("scenario segment fits u16");
    let mut frame = ethernet_header(link.dest_mac, link.src_mac, ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4_header(
        total_length,
        ttl,
        IPPROTO_UDP,
        source,
        destination,
    ));
    frame.extend_from_slice(&segment);
    frame
}

fn tcp_syn_segment(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let mut segment = vec![0_u8; 20];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&0_u32.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = 0x02;
    segment[14..16].copy_from_slice(&64_240_u16.to_be_bytes());

    let tcp_length = u16::try_from(segment.len()).expect("scenario segment fits u16");
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.push(0);
    pseudo.push(IPPROTO_TCP);
    pseudo.extend_from_slice(&tcp_length.to_be_bytes());
    pseudo.extend_from_slice(&segment);
    let checksum = internet_checksum(&pseudo);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

/// Ethernet + IPv4 + TCP SYN frame from `source`/`source_port` to
/// `destination`/`destination_port`, with a correct IPv4 and TCP checksum.
#[must_use]
pub fn tcp_syn_frame(
    link: EthernetHop,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    sequence: u32,
) -> Vec<u8> {
    let segment = tcp_syn_segment(source, destination, source_port, destination_port, sequence);
    let total_length = u16::try_from(20 + segment.len()).expect("scenario segment fits u16");
    let mut frame = ethernet_header(link.dest_mac, link.src_mac, ETHERTYPE_IPV4);
    frame.extend_from_slice(&ipv4_header(
        total_length,
        ttl,
        IPPROTO_TCP,
        source,
        destination,
    ));
    frame.extend_from_slice(&segment);
    frame
}

pub const FULL_SERVICE: &str = include_str!("../fixtures/full-service.toml");
pub const UDP_NAT: &str = include_str!("../fixtures/udp-nat.toml");
pub const DIRECT_WAN_ROUTE: &str = include_str!("../fixtures/direct-wan-route.toml");

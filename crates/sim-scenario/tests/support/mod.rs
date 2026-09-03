#![allow(dead_code)]

use ruster_core::IfId;

pub const LAN: IfId = IfId(1);
pub const WAN: IfId = IfId(2);

pub const LAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const WAN_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
pub const WAN_NEXT_HOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 3];
pub const HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 4];
pub const RESOLVABLE_HOST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 30];

pub const LAN_IP: [u8; 4] = [192, 0, 2, 1];
pub const HOST_IP: [u8; 4] = [192, 0, 2, 20];
pub const WAN_IP: [u8; 4] = [198, 51, 100, 10];
pub const REMOTE_IP: [u8; 4] = [203, 0, 113, 5];
pub const RESOLVABLE_HOST_IP: [u8; 4] = [203, 0, 113, 50];
pub const UNREACHABLE_HOST_IP: [u8; 4] = [203, 0, 113, 99];

pub const FULL_SERVICE: &str = include_str!("../fixtures/full-service-golden.toml");
pub const UDP_NAT: &str = include_str!("../fixtures/udp-nat-golden.toml");
pub const DIRECT_WAN_ROUTE: &str = include_str!("../fixtures/direct-wan-route-golden.toml");

#[derive(Clone, Copy, Debug)]
pub struct EthernetHop {
    pub dest_mac: [u8; 6],
    pub src_mac: [u8; 6],
}

pub const LAN_HOP: EthernetHop = EthernetHop {
    dest_mac: LAN_MAC,
    src_mac: HOST_MAC,
};

fn ethernet_header(destination: [u8; 6], source: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(14);
    header.extend_from_slice(&destination);
    header.extend_from_slice(&source);
    header.extend_from_slice(&ethertype.to_be_bytes());
    header
}

fn fold_ones_complement(mut sum: u32) -> u32 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

/// Independent RFC 1071 one's-complement checksum with explicit odd-byte and
/// end-around-carry handling. This is deliberately not a production helper.
pub fn independent_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let word = (u32::from(chunk[0]) << 8) | u32::from(chunk.get(1).copied().unwrap_or(0));
        sum = fold_ones_complement(sum + word);
    }
    (!fold_ones_complement(sum)) as u16
}

/// Calculates a transport checksum over a zeroed checksum field and an IPv4
/// pseudo-header. The caller chooses the final wire normalization because UDP
/// and TCP have different zero semantics.
pub fn independent_transport_checksum(ip: &[u8], protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&ip[12..16]);
    pseudo.extend_from_slice(&ip[16..20]);
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(
        &u16::try_from(segment.len())
            .expect("golden transport segment fits in an IPv4 payload")
            .to_be_bytes(),
    );
    pseudo.extend_from_slice(segment);
    independent_checksum(&pseudo)
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
    header[2..4].copy_from_slice(&total_length.to_be_bytes());
    header[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    header[8] = ttl;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source);
    header[16..20].copy_from_slice(&destination);
    let checksum = independent_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
    header
}

pub fn arp_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut frame = ethernet_header([0xff; 6], sender_mac, 0x0806);
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[6, 4]);
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target_ip);
    frame.resize(60, 0);
    frame
}

pub fn arp_reply(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = ethernet_header(target_mac, sender_mac, 0x0806);
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[6, 4]);
    frame.extend_from_slice(&2_u16.to_be_bytes());
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip);
    frame.extend_from_slice(&target_mac);
    frame.extend_from_slice(&target_ip);
    frame.resize(60, 0);
    frame
}

fn udp_segment(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = u16::try_from(8 + payload.len()).expect("golden UDP segment fits in u16");
    let mut segment = Vec::with_capacity(usize::from(length));
    segment.extend_from_slice(&source_port.to_be_bytes());
    segment.extend_from_slice(&destination_port.to_be_bytes());
    segment.extend_from_slice(&length.to_be_bytes());
    segment.extend_from_slice(&0_u16.to_be_bytes());
    segment.extend_from_slice(payload);

    let ip = {
        let mut header = [0_u8; 20];
        header[12..16].copy_from_slice(&source);
        header[16..20].copy_from_slice(&destination);
        header
    };
    let checksum = independent_transport_checksum(&ip, 17, &segment);
    let wire_checksum = if checksum == 0 { 0xffff } else { checksum };
    segment[6..8].copy_from_slice(&wire_checksum.to_be_bytes());
    segment
}

/// Builds an IPv4/UDP datagram without an Ethernet header, for ICMP quotes.
pub fn ipv4_udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let segment = udp_segment(source, destination, source_port, destination_port, payload);
    let total_length = u16::try_from(20 + segment.len()).expect("golden IPv4 packet fits in u16");
    let mut packet = ipv4_header(total_length, ttl, 17, source, destination).to_vec();
    packet.extend_from_slice(&segment);
    packet
}

pub fn udp_frame(
    link: EthernetHop,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let packet = ipv4_udp_packet(
        source,
        destination,
        source_port,
        destination_port,
        ttl,
        payload,
    );
    let mut frame = ethernet_header(link.dest_mac, link.src_mac, 0x0800);
    frame.extend_from_slice(&packet);
    frame
}

fn tcp_segment(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    window: u16,
) -> Vec<u8> {
    let mut segment = vec![0_u8; 20];
    segment[0..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = 0x02;
    segment[14..16].copy_from_slice(&window.to_be_bytes());

    let ip = {
        let mut header = [0_u8; 20];
        header[12..16].copy_from_slice(&source);
        header[16..20].copy_from_slice(&destination);
        header
    };
    let checksum = independent_transport_checksum(&ip, 6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

pub fn tcp_syn_frame(
    link: EthernetHop,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    sequence: u32,
) -> Vec<u8> {
    tcp_syn_frame_with_window(
        link,
        source,
        destination,
        source_port,
        destination_port,
        ttl,
        sequence,
        64_240,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn tcp_syn_frame_with_window(
    link: EthernetHop,
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    ttl: u8,
    sequence: u32,
    window: u16,
) -> Vec<u8> {
    let segment = tcp_segment(
        source,
        destination,
        source_port,
        destination_port,
        sequence,
        window,
    );
    let total_length = u16::try_from(20 + segment.len()).expect("golden IPv4 packet fits in u16");
    let mut frame = ethernet_header(link.dest_mac, link.src_mac, 0x0800);
    frame.extend_from_slice(&ipv4_header(total_length, ttl, 6, source, destination));
    frame.extend_from_slice(&segment);
    frame
}

#[allow(clippy::too_many_arguments)]
pub fn icmp_error_frame(
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    outer_tos: u8,
    outer_ttl: u8,
    icmp_type: u8,
    icmp_code: u8,
    quote: &[u8],
) -> Vec<u8> {
    let quote_len = quote.len();
    let ip_total_length = u16::try_from(28 + quote_len).expect("golden ICMP packet fits in u16");
    let mut frame = ethernet_header(destination_mac, source_mac, 0x0800);
    let mut ip = ipv4_header(ip_total_length, outer_ttl, 1, source_ip, destination_ip);
    ip[1] = outer_tos;
    ip[10..12].copy_from_slice(&0_u16.to_be_bytes());
    let checksum = independent_checksum(&ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.push(icmp_type);
    frame.push(icmp_code);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(quote);
    let checksum = independent_checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&checksum.to_be_bytes());
    frame
}

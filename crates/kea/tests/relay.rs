//! The DHCPv4 relay agent's requests and replies.

use std::net::Ipv4Addr;

use ruster_kea::relay::{reply, request, Dropped, Link};

const CLIENT: [u8; 6] = [0x02, 0, 0, 0, 0, 0x10];

fn link() -> Link {
    Link {
        interface: "lan".into(),
        mac: [0x02, 0, 0, 0, 0, 0x01],
        address: Ipv4Addr::new(192, 0, 2, 1),
    }
}

/// The one's complement sum, written apart from the crate's.
fn sum(bytes: &[u8]) -> u16 {
    let mut total: u32 = 0;
    for pair in bytes.chunks(2) {
        let word = u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        total += word;
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

fn udp_checksum(ip: &[u8]) -> u16 {
    let udp = &ip[20..];
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&ip[12..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    sum(&pseudo)
}

/// A BOOTP message: op, flags, ciaddr, yiaddr, giaddr, and the options after the
/// cookie.
fn message(
    op: u8,
    flags: u16,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    giaddr: [u8; 4],
    options: &[u8],
) -> Vec<u8> {
    let mut m = vec![0; 236];
    m[0] = op;
    m[1] = 1;
    m[2] = 6;
    m[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    m[10..12].copy_from_slice(&flags.to_be_bytes());
    m[12..16].copy_from_slice(&ciaddr);
    m[16..20].copy_from_slice(&yiaddr);
    m[24..28].copy_from_slice(&giaddr);
    m[28..34].copy_from_slice(&CLIENT);
    m.extend_from_slice(&[99, 130, 83, 99]);
    m.extend_from_slice(options);
    m
}

/// A client's frame: from `source` port 68 to `to` port 67.
fn frame(source: [u8; 4], to: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&CLIENT);
    f.extend_from_slice(&[0x08, 0x00]);
    let total = (28 + payload.len()) as u16;
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0]);
    ip.extend_from_slice(&source);
    ip.extend_from_slice(&to);
    let header = sum(&ip);
    ip[10..12].copy_from_slice(&header.to_be_bytes());
    ip.extend_from_slice(&68_u16.to_be_bytes());
    ip.extend_from_slice(&67_u16.to_be_bytes());
    ip.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(payload);
    let udp = udp_checksum(&ip);
    ip[26..28].copy_from_slice(&udp.to_be_bytes());
    f.extend_from_slice(&ip);
    f
}

const DISCOVER: &[u8] = &[53, 1, 1, 55, 3, 1, 3, 6, 255, 0, 0, 0];

fn discover() -> Vec<u8> {
    frame(
        [0; 4],
        [255; 4],
        &message(1, 0, [0; 4], [0; 4], [0; 4], DISCOVER),
    )
}

#[test]
fn a_request_gets_giaddr_a_hop_and_the_circuit() {
    let relayed = request(&link(), &discover()).unwrap();
    let original = message(1, 0, [0; 4], [0; 4], [0; 4], DISCOVER);
    assert_eq!(relayed[3], 1, "hops");
    assert_eq!(relayed[24..28], [192, 0, 2, 1], "giaddr");
    assert_eq!(relayed[..3], original[..3]);
    assert_eq!(relayed[4..24], original[4..24]);
    assert_eq!(relayed[28..240], original[28..240]);
    assert_eq!(
        relayed[240..],
        [53, 1, 1, 55, 3, 1, 3, 6, 82, 5, 1, 3, b'l', b'a', b'n', 255],
        "option 82 last before End, the padding gone"
    );
}

#[test]
fn a_renewal_to_the_router_is_relayed_too() {
    let payload = message(1, 0, [192, 0, 2, 100], [0; 4], [0; 4], &[53, 1, 3, 255]);
    let renewal = frame([192, 0, 2, 100], [192, 0, 2, 1], &payload);
    let relayed = request(&link(), &renewal).unwrap();
    assert_eq!(relayed[12..16], [192, 0, 2, 100], "ciaddr kept");
    assert_eq!(relayed[24..28], [192, 0, 2, 1]);
}

#[test]
fn a_request_with_no_udp_checksum_is_taken() {
    let mut f = discover();
    f[14 + 26..14 + 28].copy_from_slice(&[0, 0]);
    assert!(request(&link(), &f).is_ok());
}

#[test]
fn requests_that_cannot_be_relayed_are_dropped() {
    let with = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut m = message(1, 0, [0; 4], [0; 4], [0; 4], DISCOVER);
        change(&mut m);
        frame([0; 4], [255; 4], &m)
    };
    let cases: Vec<(Vec<u8>, Dropped)> = vec![
        (with(&|m| m[0] = 2), Dropped::Op),
        (with(&|m| m[3] = 5), Dropped::Hops),
        (
            with(&|m| m[24..28].copy_from_slice(&[10, 0, 0, 1])),
            Dropped::Giaddr,
        ),
        (
            with(&|m| m.splice(240..240, [82, 3, 1, 1, b'x']).for_each(drop)),
            Dropped::AgentOption,
        ),
        (with(&|m| m.truncate(239)), Dropped::Malformed),
        (with(&|m| m[236] = 0), Dropped::Malformed),
        (with(&|m| m.truncate(244)), Dropped::Malformed),
        (with(&|m| m[241] = 200), Dropped::Malformed),
    ];
    for (at, (frame, why)) in cases.into_iter().enumerate() {
        assert_eq!(request(&link(), &frame), Err(why), "case {at}");
    }

    let good = discover();
    let mut bad_ip = good.clone();
    bad_ip[14 + 8] = 1; // TTL changed, the checksum not
    assert_eq!(request(&link(), &bad_ip), Err(Dropped::Checksum));
    let mut bad_udp = good.clone();
    bad_udp[14 + 28 + 4] ^= 1;
    assert_eq!(request(&link(), &bad_udp), Err(Dropped::Checksum));
    let mut port = good.clone();
    port[14 + 23] = 68;
    assert_eq!(request(&link(), &port), Err(Dropped::NotDhcp));
    let mut fragment = good.clone();
    fragment[14 + 6] = 0x20;
    assert_eq!(request(&link(), &fragment), Err(Dropped::NotDhcp));
    let mut ipv6 = good.clone();
    ipv6[12..14].copy_from_slice(&[0x86, 0xdd]);
    assert_eq!(request(&link(), &ipv6), Err(Dropped::NotDhcp));
    let mut options = good;
    options[14] = 0x46;
    assert_eq!(request(&link(), &options), Err(Dropped::NotDhcp));
}

/// Kea's reply to the relay, echoing option 82.
fn kea_reply(flags: u16, ciaddr: [u8; 4], yiaddr: [u8; 4]) -> Vec<u8> {
    message(
        2,
        flags,
        ciaddr,
        yiaddr,
        [192, 0, 2, 1],
        &[
            53, 1, 2, 54, 4, 192, 0, 2, 1, 82, 5, 1, 3, b'l', b'a', b'n', 255,
        ],
    )
}

/// The destination MAC and address, and the BOOTP message, of a reply frame whose
/// headers are checked.
fn open(frame: &[u8]) -> ([u8; 6], [u8; 4], Vec<u8>) {
    assert_eq!(frame[6..12], link().mac);
    assert_eq!(frame[12..14], [0x08, 0x00]);
    let ip = &frame[14..];
    assert_eq!(ip[0], 0x45);
    assert_eq!(usize::from(u16::from_be_bytes([ip[2], ip[3]])), ip.len());
    assert_eq!(sum(&ip[..20]), 0, "IPv4 header checksum");
    assert_eq!(ip[9], 17);
    assert_eq!(ip[12..16], [192, 0, 2, 1]);
    assert_eq!(ip[20..24], [0, 67, 0, 68], "ports");
    assert_eq!(
        usize::from(u16::from_be_bytes([ip[24], ip[25]])),
        ip.len() - 20
    );
    assert_eq!(udp_checksum(ip), 0, "UDP checksum");
    (
        frame[..6].try_into().unwrap(),
        ip[16..20].try_into().unwrap(),
        ip[28..].to_vec(),
    )
}

#[test]
fn a_reply_goes_to_the_client_without_option_82() {
    let (mac, to, message) =
        open(&reply(&link(), &kea_reply(0, [0; 4], [192, 0, 2, 100])).unwrap());
    assert_eq!(mac, CLIENT);
    assert_eq!(to, [192, 0, 2, 100]);
    assert_eq!(message[240..], [53, 1, 2, 54, 4, 192, 0, 2, 1, 255]);
    assert_eq!(
        message[..240],
        kea_reply(0, [0; 4], [192, 0, 2, 100])[..240]
    );
}

#[test]
fn a_reply_is_broadcast_when_the_client_asks_or_has_no_address() {
    for (flags, ciaddr, yiaddr) in [
        (0x8000, [0; 4], [192, 0, 2, 100]),
        (0, [0; 4], [0; 4]), // a DHCPNAK
    ] {
        let (mac, to, _) = open(&reply(&link(), &kea_reply(flags, ciaddr, yiaddr)).unwrap());
        assert_eq!((mac, to), ([0xff; 6], [255; 4]), "{flags:x} {yiaddr:?}");
    }
    // An answer to DHCPINFORM has no yiaddr and goes to ciaddr.
    let (mac, to, _) = open(&reply(&link(), &kea_reply(0, [192, 0, 2, 50], [0; 4])).unwrap());
    assert_eq!((mac, to), (CLIENT, [192, 0, 2, 50]));
    // A hardware address that is not Ethernet's is broadcast to.
    let mut other = kea_reply(0, [0; 4], [192, 0, 2, 100]);
    other[1] = 6;
    let (mac, to, _) = open(&reply(&link(), &other).unwrap());
    assert_eq!((mac, to), ([0xff; 6], [255; 4]));
}

#[test]
fn replies_that_are_not_for_the_link_are_dropped() {
    let mut other = kea_reply(0, [0; 4], [192, 0, 2, 100]);
    other[24..28].copy_from_slice(&[192, 0, 2, 2]);
    assert_eq!(reply(&link(), &other), Err(Dropped::Giaddr));
    let mut op = kea_reply(0, [0; 4], [192, 0, 2, 100]);
    op[0] = 1;
    assert_eq!(reply(&link(), &op), Err(Dropped::Op));
    let mut long = kea_reply(0, [0; 4], [192, 0, 2, 100]);
    long.pop();
    for _ in 0..6 {
        long.extend_from_slice(&[43, 255]);
        long.extend_from_slice(&[0; 255]);
    }
    long.push(255);
    assert_eq!(reply(&link(), &long), Err(Dropped::TooLong));
    let mut cut = kea_reply(0, [0; 4], [192, 0, 2, 100]);
    cut.truncate(250);
    assert_eq!(reply(&link(), &cut), Err(Dropped::Malformed));
}

#[test]
fn no_input_makes_it_panic() {
    // Every cut of good messages, and pseudo-random bytes over them.
    let good = discover();
    let kea = kea_reply(0, [0; 4], [192, 0, 2, 100]);
    for len in 0..=good.len() {
        let _ = request(&link(), &good[..len]);
    }
    for len in 0..=kea.len() {
        let _ = reply(&link(), &kea[..len]);
    }
    let mut state: u32 = 1;
    for _ in 0..20_000 {
        let mut f = good.clone();
        let mut k = kea.clone();
        for _ in 0..4 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let at = (state >> 8) as usize;
            let byte = (state >> 24) as u8;
            f[at % good.len()] = byte;
            k[at % kea.len()] = byte;
        }
        let _ = request(&link(), &f);
        let _ = reply(&link(), &k);
    }
}

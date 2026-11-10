//! The DHCPv6 relay agent's messages (RFC 8415 sections 9, 19 and 21).

use std::net::Ipv6Addr;

use ruster_kea::relay6::{frame, reply, request, Dropped, Link6};

const LAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const CLIENT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x10];

fn ip(text: &str) -> Ipv6Addr {
    text.parse().unwrap()
}

fn link() -> Link6 {
    Link6 {
        interface: "lan".into(),
        mac: LAN_MAC,
        link_local: ip("fe80::ff:fe00:1"),
        address: ip("2001:db8:1::1"),
    }
}

fn checksum(source: Ipv6Addr, destination: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.extend_from_slice(&u32::try_from(udp.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 17]);
    bytes.extend_from_slice(udp);
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A client's message from fe80::10, port 546, to ff02::1:2, port 547.
fn client_frame(message: &[u8], next_header: u8) -> Vec<u8> {
    let source = ip("fe80::10");
    let to = ip("ff02::1:2");
    let mut udp = Vec::new();
    udp.extend_from_slice(&546_u16.to_be_bytes());
    udp.extend_from_slice(&547_u16.to_be_bytes());
    udp.extend_from_slice(&u16::try_from(8 + message.len()).unwrap().to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(message);
    let sum = checksum(source, to, &udp);
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    let mut out = vec![0x33, 0x33, 0, 1, 0, 2];
    out.extend_from_slice(&CLIENT_MAC);
    out.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    out.extend_from_slice(&u16::try_from(udp.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[next_header, 1]);
    out.extend_from_slice(&source.octets());
    out.extend_from_slice(&to.octets());
    out.extend_from_slice(&udp);
    out
}

/// A Solicit with a Client Identifier option.
const SOLICIT: &[u8] = &[1, 0xaa, 0xbb, 0xcc, 0, 1, 0, 4, 1, 2, 3, 4];

fn option(code: u16, value: &[u8]) -> Vec<u8> {
    let mut out = code.to_be_bytes().to_vec();
    out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    out.extend_from_slice(value);
    out
}

#[test]
fn a_client_message_is_relayed_with_the_link_and_the_client() {
    let relayed = request(&link(), &client_frame(SOLICIT, 17)).unwrap();
    assert_eq!(relayed.client, ip("fe80::10"));
    assert_eq!(relayed.client_mac, CLIENT_MAC);
    let mut want = vec![12, 0];
    want.extend_from_slice(&ip("2001:db8:1::1").octets());
    want.extend_from_slice(&ip("fe80::10").octets());
    want.extend(option(18, b"lan"));
    want.extend(option(79, &[0, 1, 2, 0, 0, 0, 0, 0x10]));
    want.extend(option(9, SOLICIT));
    assert_eq!(relayed.message, want);
}

#[test]
fn what_a_client_does_not_send_is_dropped() {
    for kind in [2, 7, 10, 12, 13] {
        let mut message = SOLICIT.to_vec();
        message[0] = kind;
        assert_eq!(
            request(&link(), &client_frame(&message, 17)),
            Err(Dropped::Type),
            "type {kind}"
        );
    }
    let mut bad_sum = client_frame(SOLICIT, 17);
    let at = bad_sum.len() - 1;
    bad_sum[at] ^= 1;
    assert_eq!(request(&link(), &bad_sum), Err(Dropped::Checksum));
    let mut no_sum = client_frame(SOLICIT, 17);
    no_sum[14 + 40 + 6..14 + 40 + 8].copy_from_slice(&[0, 0]);
    assert_eq!(request(&link(), &no_sum), Err(Dropped::Checksum));
    // A hop-by-hop header before UDP.
    assert_eq!(
        request(&link(), &client_frame(SOLICIT, 0)),
        Err(Dropped::NotDhcp)
    );
    let short = client_frame(&SOLICIT[..3], 17);
    assert_eq!(request(&link(), &short), Err(Dropped::Malformed));
    let frame = client_frame(SOLICIT, 17);
    for cut in 0..frame.len() {
        assert!(request(&link(), &frame[..cut]).is_err(), "cut at {cut}");
    }
}

/// Kea's Relay-reply carrying `inner` for fe80::10.
fn relay_reply(link_address: &str, hops: u8, options: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![13, hops];
    out.extend_from_slice(&ip(link_address).octets());
    out.extend_from_slice(&ip("fe80::10").octets());
    for o in options {
        out.extend_from_slice(o);
    }
    out
}

const ADVERTISE: &[u8] = &[2, 0xaa, 0xbb, 0xcc, 0, 1, 0, 4, 1, 2, 3, 4];

#[test]
fn a_relay_reply_goes_to_the_client() {
    let message = relay_reply(
        "2001:db8:1::1",
        0,
        &[option(18, b"lan"), option(9, ADVERTISE)],
    );
    let (to, inner) = reply(&link(), &message).unwrap();
    assert_eq!(to, ip("fe80::10"));
    assert_eq!(inner, ADVERTISE);
    let out = frame(&link(), CLIENT_MAC, to, inner).unwrap();
    assert_eq!(&out[0..6], &CLIENT_MAC);
    assert_eq!(&out[6..12], &LAN_MAC);
    assert_eq!(&out[12..14], &[0x86, 0xdd]);
    assert_eq!(out[14 + 6], 17);
    assert_eq!(&out[22..38], &ip("fe80::ff:fe00:1").octets());
    assert_eq!(&out[38..54], &ip("fe80::10").octets());
    assert_eq!(&out[54..56], &547_u16.to_be_bytes());
    assert_eq!(&out[56..58], &546_u16.to_be_bytes());
    assert_eq!(
        usize::from(u16::from_be_bytes([out[18], out[19]])),
        out.len() - 54
    );
    assert_eq!(
        checksum(ip("fe80::ff:fe00:1"), ip("fe80::10"), &out[54..]),
        0
    );
    assert_eq!(&out[62..], ADVERTISE);
    // Without Interface-Id it is taken too.
    assert!(reply(
        &link(),
        &relay_reply("2001:db8:1::1", 0, &[option(9, ADVERTISE)])
    )
    .is_ok());
    assert_eq!(
        frame(&link(), CLIENT_MAC, to, &[0; 1500]),
        Err(Dropped::TooLong)
    );
}

#[test]
fn a_relay_reply_for_another_link_or_broken_is_dropped() {
    let good = [option(18, b"lan"), option(9, ADVERTISE)];
    for (message, error) in [
        (relay_reply("2001:db8:2::1", 0, &good), Dropped::Link),
        (relay_reply("2001:db8:1::1", 1, &good), Dropped::Link),
        (
            relay_reply(
                "2001:db8:1::1",
                0,
                &[option(18, b"wan"), option(9, ADVERTISE)],
            ),
            Dropped::Link,
        ),
        (
            relay_reply("2001:db8:1::1", 0, &[option(18, b"lan")]),
            Dropped::Malformed,
        ),
        (
            relay_reply("2001:db8:1::1", 0, &[option(9, SOLICIT)]),
            Dropped::Type,
        ),
        (
            relay_reply("2001:db8:1::1", 0, &[option(9, &[2, 0])]),
            Dropped::Malformed,
        ),
    ] {
        assert_eq!(reply(&link(), &message), Err(error));
    }
    let twice = relay_reply(
        "2001:db8:1::1",
        0,
        &[option(9, ADVERTISE), option(9, ADVERTISE)],
    );
    assert_eq!(reply(&link(), &twice), Err(Dropped::Malformed));
    let mut forward = relay_reply("2001:db8:1::1", 0, &good);
    forward[0] = 12;
    assert_eq!(reply(&link(), &forward), Err(Dropped::Type));
    let whole = relay_reply("2001:db8:1::1", 0, &good);
    for cut in 0..whole.len() {
        assert!(reply(&link(), &whole[..cut]).is_err(), "cut at {cut}");
    }
}

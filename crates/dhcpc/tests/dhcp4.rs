//! DHCPv4 messages: what the client sends and how it reads replies (RFC 2131,
//! RFC 2132).

use std::net::Ipv4Addr;

use ruster_dhcpc::dhcp4::{kind, mask_len, Reply, Request};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

/// The options of a message, after the cookie, as (code, value).
fn options(message: &[u8]) -> Vec<(u8, Vec<u8>)> {
    assert_eq!(&message[236..240], &[99, 130, 83, 99]);
    let mut out = Vec::new();
    let mut at = 240;
    while message[at] != 255 {
        if message[at] == 0 {
            at += 1;
            continue;
        }
        let len = usize::from(message[at + 1]);
        out.push((message[at], message[at + 2..at + 2 + len].to_vec()));
        at += 2 + len;
    }
    out
}

/// A server's reply with `options` (code, value).
fn reply(kind: u8, xid: u32, yiaddr: [u8; 4], options: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![0; 236];
    out[0] = 2;
    out[1] = 1;
    out[2] = 6;
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[16..20].copy_from_slice(&yiaddr);
    out[28..34].copy_from_slice(&MAC);
    out.extend_from_slice(&[99, 130, 83, 99, 53, 1, kind]);
    for (code, value) in options {
        out.push(*code);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }
    out.push(255);
    out
}

#[test]
fn a_discover_asks_for_a_broadcast_answer_and_the_options_we_use() {
    let message = Request {
        kind: kind::DISCOVER,
        xid: 0x1234_5678,
        secs: 3,
        mac: MAC,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        requested: None,
        server: None,
    }
    .encode();
    assert!(message.len() >= 300);
    assert_eq!(&message[..4], &[1, 1, 6, 0]);
    assert_eq!(&message[4..8], &[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(&message[8..10], &[0, 3]);
    // RFC 2131 section 4.1: the BROADCAST flag.
    assert_eq!(&message[10..12], &[0x80, 0]);
    assert_eq!(&message[28..34], &MAC);
    let options = options(&message);
    assert_eq!(options[0], (53, vec![1]));
    let asked = options.iter().find(|(c, _)| *c == 55).unwrap();
    for wanted in [1, 3, 6, 51, 58, 59] {
        assert!(asked.1.contains(&wanted));
    }
}

#[test]
fn requests_carry_the_requested_address_and_server_and_a_release_no_flag() {
    let request = Request {
        kind: kind::REQUEST,
        xid: 1,
        secs: 0,
        mac: MAC,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        requested: Some(Ipv4Addr::new(198, 51, 100, 20)),
        server: Some(Ipv4Addr::new(198, 51, 100, 1)),
    }
    .encode();
    let options = options(&request);
    assert!(options.contains(&(50, vec![198, 51, 100, 20])));
    assert!(options.contains(&(54, vec![198, 51, 100, 1])));
    let release = Request {
        kind: kind::RELEASE,
        xid: 2,
        secs: 0,
        mac: MAC,
        ciaddr: Ipv4Addr::new(198, 51, 100, 20),
        requested: None,
        server: Some(Ipv4Addr::new(198, 51, 100, 1)),
    }
    .encode();
    assert_eq!(&release[10..12], &[0, 0]);
    assert_eq!(&release[12..16], &[198, 51, 100, 20]);
    assert!(!self::options(&release).iter().any(|(c, _)| *c == 55));
}

#[test]
fn a_reply_gives_its_options() {
    let message = reply(
        kind::ACK,
        7,
        [198, 51, 100, 20],
        &[
            (54, &[198, 51, 100, 1]),
            (1, &[255, 255, 255, 0]),
            (3, &[198, 51, 100, 1, 198, 51, 100, 2]),
            (6, &[192, 0, 2, 53]),
            (51, &[0, 0, 0x0e, 0x10]),
            (58, &[0, 0, 0x07, 0x08]),
            (59, &[0, 0, 0x0c, 0x4e]),
            (99, &[1, 2, 3]),
        ],
    );
    let reply = Reply::parse(&message).unwrap();
    assert_eq!(reply.kind, kind::ACK);
    assert_eq!(reply.xid, 7);
    assert_eq!(reply.yiaddr, Ipv4Addr::new(198, 51, 100, 20));
    assert_eq!(reply.server, Some(Ipv4Addr::new(198, 51, 100, 1)));
    assert_eq!(reply.subnet_mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
    assert_eq!(reply.routers.len(), 2);
    assert_eq!(reply.dns, [Ipv4Addr::new(192, 0, 2, 53)]);
    assert_eq!(reply.lease_time, Some(3600));
    assert_eq!((reply.t1, reply.t2), (Some(1800), Some(3150)));
}

#[test]
fn malformed_replies_are_not_read() {
    let good = reply(kind::OFFER, 7, [198, 51, 100, 20], &[(54, &[1, 2, 3, 4])]);
    assert!(Reply::parse(&good).is_some());
    // Cut short anywhere.
    for len in [0, 100, 236, 239, 243, good.len() - 1] {
        assert!(Reply::parse(&good[..len]).is_none(), "{len}");
    }
    // A request, not a reply.
    let mut request = good.clone();
    request[0] = 1;
    assert!(Reply::parse(&request).is_none());
    let mut cookie = good.clone();
    cookie[239] = 0;
    assert!(Reply::parse(&cookie).is_none());
    // An option running past the end.
    let mut long = good[..good.len() - 1].to_vec();
    long.extend_from_slice(&[6, 200, 1, 2]);
    assert!(Reply::parse(&long).is_none());
    // No message type.
    let mut none = good.clone();
    none[242] = 0;
    assert!(Reply::parse(&none).is_none());
    // Lists of the wrong length give none; pads are skipped.
    let odd = reply(kind::ACK, 7, [0; 4], &[(0, &[]), (3, &[1, 2, 3])]);
    let parsed = Reply::parse(&odd);
    assert!(parsed.is_none() || parsed.unwrap().routers.is_empty());
}

#[test]
fn subnet_masks_are_prefix_lengths_only_when_contiguous() {
    assert_eq!(mask_len(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
    assert_eq!(mask_len(Ipv4Addr::new(255, 255, 255, 255)), Some(32));
    assert_eq!(mask_len(Ipv4Addr::new(0, 0, 0, 0)), Some(0));
    assert_eq!(mask_len(Ipv4Addr::new(255, 0, 255, 0)), None);
}

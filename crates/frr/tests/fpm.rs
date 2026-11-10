//! Reading FPM: frames zebra (FRR 10.5) sent, frames made here, and truncated and
//! mutated ones, which must give errors, never a panic.

use std::net::IpAddr;

use ruster_frr::fpm::{messages, next_frame, FrameError, Hop, Kind, Message, Route, HEADER};

/// What zebra sent for a connected route (198.51.100.0/24 on ifindex 3), a BGP route
/// (203.0.113.0/24 via 198.51.100.10) and a BGP IPv6 route (2001:db8:203::/64 via a
/// link-local gateway), each frame as it came.
const ZEBRA: &[&str] = &[
    "0101003834000000180001050000000028ea469602180000fe0200010000000008000100c633640008000600140000000800040003000000",
    "010100403c000000180001050000000028ea469602180000feba00010000000008000100cb007100080006001400000008000500c633640a0800040003000000",
    "0101005854000000180001050000000028ea46960a400000feba0001000000001400010020010db8020300000000000000000000080006001400000014000500fe800000000000008ce81bfffeec95e70800040003000000",
];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn routes(frame: &[u8]) -> Vec<Route> {
    let (body, used) = next_frame(frame).unwrap().unwrap();
    assert_eq!(used, frame.len());
    messages(body)
        .into_iter()
        .map(|m| match m.unwrap() {
            Message::Route(r) => r,
            Message::Ignored => panic!("ignored"),
        })
        .collect()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn zebra_s_frames_are_read() {
    let frames: Vec<Vec<u8>> = ZEBRA.iter().map(|f| hex(f)).collect();
    let connected = &routes(&frames[0])[0];
    assert_eq!(
        *connected,
        Route {
            new: true,
            prefix: ip("198.51.100.0"),
            len: 24,
            table: 254,
            kind: Kind::Unicast,
            hops: vec![Hop {
                gateway: None,
                oif: Some(3)
            }],
        }
    );
    let bgp = &routes(&frames[1])[0];
    assert_eq!((bgp.prefix, bgp.len), (ip("203.0.113.0"), 24));
    assert_eq!(
        bgp.hops,
        [Hop {
            gateway: Some(ip("198.51.100.10")),
            oif: Some(3)
        }]
    );
    let v6 = &routes(&frames[2])[0];
    assert_eq!((v6.prefix, v6.len), (ip("2001:db8:203::"), 64));
    assert_eq!(v6.hops[0].gateway, Some(ip("fe80::8ce8:1bff:feec:95e7")));
}

// Builders for netlink route messages, in the host's byte order.
fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = ((4 + value.len()) as u16).to_ne_bytes().to_vec();
    out.extend(kind.to_ne_bytes());
    out.extend(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn nexthop(gateway: &[u8], ifindex: u32) -> Vec<u8> {
    let inner = attr(5, gateway);
    let mut out = ((8 + inner.len()) as u16).to_ne_bytes().to_vec();
    out.extend([0, 0]);
    out.extend(ifindex.to_ne_bytes());
    out.extend(inner);
    out
}

fn message(kind: u16, family: u8, len: u8, table: u8, rtype: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = [family, len, 0, 0, table, 186, 0, rtype, 0, 0, 0, 0]
        .into_iter()
        .chain(attrs.iter().flatten().copied())
        .collect();
    let mut out = ((16 + body.len()) as u32).to_ne_bytes().to_vec();
    out.extend(kind.to_ne_bytes());
    out.extend(0x0501u16.to_ne_bytes());
    out.extend([0; 8]);
    out.extend(body);
    out
}

fn frame(messages: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = messages.concat();
    let mut out = vec![1, 1];
    out.extend(((HEADER + body.len()) as u16).to_be_bytes());
    out.extend(body);
    out
}

/// An update as zebra sends it: the delete and the new route in one frame, the new
/// one with two next hops and its table in RTA_TABLE.
fn update() -> Vec<u8> {
    let multipath: Vec<u8> = [nexthop(&[10, 0, 0, 1], 3), nexthop(&[10, 0, 1, 1], 3)].concat();
    frame(&[
        message(25, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0])]),
        message(
            24,
            2,
            8,
            252,
            1,
            &[
                attr(1, &[10, 0, 0, 0]),
                attr(15, &254u32.to_ne_bytes()),
                attr(9, &multipath),
            ],
        ),
    ])
}

#[test]
fn an_update_has_both_messages_and_every_next_hop() {
    let got = routes(&update());
    assert_eq!(got.len(), 2);
    assert!(!got[0].new && got[1].new);
    assert_eq!(got[1].table, 254, "RTA_TABLE over rtm_table");
    let gateways: Vec<_> = got[1].hops.iter().map(|h| h.gateway.unwrap()).collect();
    assert_eq!(gateways, [ip("10.0.0.1"), ip("10.0.1.1")]);
}

#[test]
fn routes_without_rta_dst_and_of_other_kinds() {
    let default = frame(&[message(
        24,
        10,
        0,
        254,
        1,
        &[attr(
            5,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        )],
    )]);
    assert_eq!(routes(&default)[0].prefix, ip("::"));
    let blackhole = frame(&[message(24, 2, 8, 254, 6, &[attr(1, &[10, 0, 0, 0])])]);
    assert_eq!(routes(&blackhole)[0].kind, Kind::Blackhole);
    let prohibit = frame(&[message(24, 2, 8, 254, 8, &[attr(1, &[10, 0, 0, 0])])]);
    assert_eq!(routes(&prohibit)[0].kind, Kind::Unreachable);
    // Another family, another message type, and a source prefix are passed over.
    let mpls = frame(&[message(24, 28, 20, 254, 1, &[])]);
    let link = frame(&[message(16, 0, 0, 0, 0, &[])]);
    let mut sourced = message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0])]);
    sourced[18] = 8;
    for f in [mpls, link, frame(&[sourced])] {
        let (body, _) = next_frame(&f).unwrap().unwrap();
        assert_eq!(messages(body), [Ok(Message::Ignored)]);
    }
}

#[test]
fn bad_messages_give_reasons() {
    let bad = |m: Vec<u8>| {
        let f = frame(&[m]);
        let (body, _) = next_frame(&f).unwrap().unwrap();
        messages(body).remove(0).unwrap_err()
    };
    assert!(bad(message(24, 2, 33, 254, 1, &[])).contains("prefix length"));
    assert!(bad(message(24, 2, 8, 254, 1, &[])).contains("no RTA_DST"));
    assert!(bad(message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 1])])).contains("host bits"));
    assert!(bad(message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0])])).contains("RTA_DST of 3"));
    assert!(bad(message(
        24,
        2,
        8,
        254,
        1,
        &[attr(1, &[10, 0, 0, 0]), attr(30, &[1, 0, 0, 0])]
    ))
    .contains("RTA_NH_ID"));
    let too_many: Vec<u8> = (0..65).flat_map(|_| nexthop(&[10, 0, 0, 1], 3)).collect();
    assert!(bad(message(
        24,
        2,
        8,
        254,
        1,
        &[attr(1, &[10, 0, 0, 0]), attr(9, &too_many)]
    ))
    .contains("more than 64"));
}

#[test]
fn frames_wait_for_their_bytes_and_bad_headers_end_the_stream() {
    let whole = update();
    for cut in 0..whole.len() {
        assert_eq!(next_frame(&whole[..cut]), Ok(None), "cut at {cut}");
    }
    assert_eq!(
        next_frame(&[2, 1, 0, 8, 0, 0, 0, 0]),
        Err(FrameError::Kind {
            version: 2,
            kind: 1
        })
    );
    assert_eq!(
        next_frame(&[1, 2, 0, 8, 0, 0, 0, 0]),
        Err(FrameError::Kind {
            version: 1,
            kind: 2
        })
    );
    assert_eq!(next_frame(&[1, 1, 0, 3]), Err(FrameError::Length(3)));
    // An empty frame has no messages; two frames are read one at a time.
    let mut two = vec![1, 1, 0, 4];
    two.extend(update());
    let (body, used) = next_frame(&two).unwrap().unwrap();
    assert!(body.is_empty() && messages(body).is_empty() && used == 4);
    assert_eq!(next_frame(&two[used..]).unwrap().unwrap().1, two.len() - 4);
}

/// xorshift64: the same mutations each run.
struct Rand(u64);

impl Rand {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Reads a whole stream the way the server does, checking what comes out.
fn read_all(mut buf: &[u8]) {
    while let Ok(Some((body, used))) = next_frame(buf) {
        assert!(used >= HEADER && used <= buf.len());
        for m in messages(body) {
            if let Ok(Message::Route(r)) = m {
                let max = if r.prefix.is_ipv4() { 32 } else { 128 };
                assert!(r.len <= max);
                assert!(r.hops.len() <= ruster_frr::fpm::HOPS_MAX);
                for hop in &r.hops {
                    assert!(hop
                        .gateway
                        .is_none_or(|g| g.is_ipv4() == r.prefix.is_ipv4()));
                }
            }
        }
        buf = &buf[used..];
    }
}

#[test]
fn truncated_and_mutated_input_never_panics() {
    let mut seeds: Vec<Vec<u8>> = ZEBRA.iter().map(|f| hex(f)).collect();
    seeds.push(update());
    let stream: Vec<u8> = seeds.concat();
    // Every truncation of the stream, and of each message inside a whole frame.
    for cut in 0..=stream.len() {
        read_all(&stream[..cut]);
    }
    for seed in &seeds {
        for cut in HEADER..seed.len() {
            let mut f = seed[..cut].to_vec();
            f[2..4].copy_from_slice(&(cut as u16).to_be_bytes());
            read_all(&f);
        }
    }
    let mut rand = Rand(0x9e37_79b9_7f4a_7c15);
    for _ in 0..200_000 {
        let mut f = seeds[(rand.next() % seeds.len() as u64) as usize].clone();
        for _ in 0..=rand.next() % 4 {
            let at = (rand.next() % f.len() as u64) as usize;
            match rand.next() % 3 {
                0 => f[at] = rand.next() as u8,
                1 => f[at] ^= 1 << (rand.next() % 8),
                _ => f[at] = [0, 0xff, 0x7f, 0x80, 4, 16][(rand.next() % 6) as usize],
            }
        }
        // Keep the frame header right half the time, so the messages get mutated.
        if rand.next().is_multiple_of(2) {
            f[0] = 1;
            f[1] = 1;
            let len = f.len() as u16;
            f[2..4].copy_from_slice(&len.to_be_bytes());
        }
        read_all(&f);
    }
}

// RFC 3549 section 2.3.2 and section 3.1.1, with Linux's values: what each field of
// a route message means, built here field by field.

fn body(f: &[u8]) -> Vec<Result<Message, String>> {
    let (body, used) = next_frame(f).unwrap().unwrap();
    assert_eq!(used, f.len());
    messages(body)
}

#[test]
fn the_fpm_length_counts_its_own_four_bytes() {
    // FRR's `fpm/fpm.h` (not an RFC): version 1, type 1 (netlink), the length in
    // network byte order with the header. A frame of one 36-byte message is 40.
    let m = message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0])]);
    assert_eq!(m.len(), 16 + 12 + 8);
    let f = frame(std::slice::from_ref(&m));
    assert_eq!(&f[..4], &[1, 1, 0, 40]);
    let (inner, used) = next_frame(&f).unwrap().unwrap();
    assert_eq!((inner, used), (&m[..], 40));
    // A length of exactly the header is a frame with no messages.
    assert_eq!(next_frame(&[1, 1, 0, 4]), Ok(Some((&[][..], 4))));
}

#[test]
fn attributes_are_aligned_to_four_bytes_and_unknown_ones_are_passed_over() {
    // RFC 3549 section 3.1.1: rta_len counts the 4-byte header and the value, not
    // the padding; the next attribute starts at RTA_ALIGN(rta_len). An unknown
    // attribute of 5 bytes (type 200) with 3 bytes of padding, RTA_PRIORITY (6), and
    // RTA_METRICS (8) with NLA_F_NESTED (0x8000) are all passed over.
    let mut odd = attr(200, &[0xaa]);
    assert_eq!((odd[0], odd.len()), (5, 8));
    odd[5..8].copy_from_slice(&[0xff; 3]); // the padding is not read
    let metrics = attr(8 | 0x8000, &attr(2, &1400u32.to_ne_bytes()));
    let m = message(
        24,
        2,
        24,
        254,
        1,
        &[
            odd,
            attr(1, &[192, 0, 2, 0]),
            attr(6, &20u32.to_ne_bytes()),
            metrics,
            attr(5, &[198, 51, 100, 1]),
            attr(4, &7u32.to_ne_bytes()),
        ],
    );
    assert_eq!(
        body(&frame(&[m])),
        [Ok(Message::Route(Route {
            new: true,
            prefix: ip("192.0.2.0"),
            len: 24,
            table: 254,
            kind: Kind::Unicast,
            hops: vec![Hop {
                gateway: Some(ip("198.51.100.1")),
                oif: Some(7)
            }],
        }))]
    );
}

#[test]
fn a_message_ending_off_four_bytes_is_followed_by_the_next_at_its_alignment() {
    // RFC 3549 section 2.3.2: nlmsg_len counts the message without its trailing
    // padding; the next starts at NLMSG_ALIGN(nlmsg_len). The first message ends
    // with a 5-byte attribute: nlmsg_len 16 + 12 + 8 + 5 = 41, the next at 44.
    let mut first = message(25, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0])]);
    first.extend([5, 0, 200, 0, 0xaa]);
    let len = first.len() as u32;
    assert_eq!(len, 41);
    first[..4].copy_from_slice(&len.to_ne_bytes());
    first.extend([0; 3]);
    let second = message(24, 2, 16, 254, 1, &[attr(1, &[10, 1, 0, 0])]);
    let got: Vec<_> = routes(&frame(&[first, second]))
        .into_iter()
        .map(|r| (r.new, r.prefix, r.len))
        .collect();
    assert_eq!(
        got,
        [(false, ip("10.0.0.0"), 8), (true, ip("10.1.0.0"), 16)]
    );
}

#[test]
fn ipv6_routes_with_rtnexthops_and_deletes() {
    // RFC 3549 section 3.1.1 and linux/rtnetlink.h: RTA_MULTIPATH is a list of
    // `struct rtnexthop` {rtnh_len u16, rtnh_flags u8, rtnh_hops u8, rtnh_ifindex
    // i32}, each followed by its own attributes. One hop here has a gateway, the
    // other only an interface.
    let gw = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut bare = 8u16.to_ne_bytes().to_vec();
    bare.extend([0, 0]);
    bare.extend(9u32.to_ne_bytes());
    let multipath: Vec<u8> = [nexthop(&gw, 4), bare].concat();
    let dst = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let new = message(24, 10, 48, 254, 1, &[attr(1, &dst), attr(9, &multipath)]);
    let del = message(25, 10, 48, 254, 1, &[attr(1, &dst)]);
    let got = routes(&frame(&[new, del]));
    assert_eq!(
        got[0].hops,
        [
            Hop {
                gateway: Some(ip("fe80::2")),
                oif: Some(4)
            },
            Hop {
                gateway: None,
                oif: Some(9)
            }
        ]
    );
    assert_eq!((got[0].prefix, got[0].len), (ip("2001:db8:10::"), 48));
    assert!(!got[1].new && got[1].hops.is_empty());
    assert_eq!((got[1].prefix, got[1].len), (ip("2001:db8:10::"), 48));
    // A /129 is not an IPv6 prefix, and a 4-byte gateway is not one of AF_INET6.
    let long = message(24, 10, 129, 254, 1, &[]);
    assert!(body(&frame(&[long]))[0]
        .as_ref()
        .unwrap_err()
        .contains("prefix length"));
    let wrong = message(
        24,
        10,
        48,
        254,
        1,
        &[attr(1, &dst), attr(5, &[198, 51, 100, 1])],
    );
    assert!(body(&frame(&[wrong]))[0]
        .as_ref()
        .unwrap_err()
        .contains("RTA_GATEWAY of 4 bytes in family 10"));
}

#[test]
fn rtm_type_and_rta_table_take_linux_s_values() {
    // linux/rtnetlink.h: RTN_UNICAST 1, RTN_LOCAL 2, RTN_BLACKHOLE 6,
    // RTN_UNREACHABLE 7, RTN_PROHIBIT 8. RTA_TABLE (a u32) holds the table when it
    // is set, as it must be above 255 (rtm_table is then RT_TABLE_COMPAT, 252).
    let of = |rtype: u8, attrs: &[Vec<u8>]| {
        let mut all = vec![attr(1, &[10, 0, 0, 0])];
        all.extend_from_slice(attrs);
        routes(&frame(&[message(24, 2, 8, 252, rtype, &all)])).remove(0)
    };
    assert_eq!(of(7, &[]).kind, Kind::Unreachable);
    assert_eq!(of(2, &[]).kind, Kind::Other(2));
    assert_eq!(of(1, &[]).table, 252);
    assert_eq!(of(1, &[attr(15, &1000u32.to_ne_bytes())]).table, 1000);
    // RTA_TABLE or RTA_OIF of another size than a u32 is refused.
    for bad in [attr(15, &[1, 0]), attr(4, &[1, 0, 0, 0, 0])] {
        let m = message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0]), bad]);
        assert!(body(&frame(&[m]))[0].is_err());
    }
}

#[test]
fn lengths_that_do_not_fit_are_refused() {
    // RFC 3549 sections 2.3.2 and 3.1.1: nlmsg_len below the 16-byte header or
    // beyond what is left, an rtmsg cut short, rta_len below 4 or beyond the
    // message, and rtnh_len below the 8-byte rtnexthop.
    let mut short = message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0])]);
    short[..4].copy_from_slice(&15u32.to_ne_bytes());
    let mut long = message(24, 2, 8, 254, 1, &[attr(1, &[10, 0, 0, 0])]);
    long[..4].copy_from_slice(&100u32.to_ne_bytes());
    let mut cut = message(24, 2, 8, 254, 1, &[]);
    cut.truncate(16 + 8);
    cut[..4].copy_from_slice(&24u32.to_ne_bytes());
    for (m, why) in [
        (short, "does not fit"),
        (long, "does not fit"),
        (cut, "a route message of 8 bytes"),
    ] {
        let got = body(&frame(&[m]));
        assert!(got[0].as_ref().unwrap_err().contains(why), "{got:?}");
    }
    let mut tiny = attr(1, &[10, 0, 0, 0]);
    tiny[..2].copy_from_slice(&3u16.to_ne_bytes());
    let mut over = attr(1, &[10, 0, 0, 0]);
    over[..2].copy_from_slice(&40u16.to_ne_bytes());
    let mut rtnh = nexthop(&[10, 0, 0, 1], 3);
    rtnh[..2].copy_from_slice(&4u16.to_ne_bytes());
    for attrs in [
        vec![tiny],
        vec![over],
        vec![attr(1, &[10, 0, 0, 0]), attr(9, &rtnh)],
    ] {
        let got = body(&frame(&[message(24, 2, 8, 254, 1, &attrs)]));
        assert!(
            got[0].as_ref().unwrap_err().contains("does not fit"),
            "{got:?}"
        );
    }
}

//! The DHCPv4 client's states (RFC 2131 section 4.4).

use std::net::Ipv4Addr;

use ruster_dhcpc::client4::{Client, Event, Lease, Output, Send, State, To, REQUEST_TRIES};
use ruster_dhcpc::dhcp4::kind;

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

fn xid(send: &Send) -> u32 {
    u32::from_be_bytes(send.payload[4..8].try_into().unwrap())
}

fn kind_of(send: &Send) -> u8 {
    assert_eq!(&send.payload[240..242], &[53, 1]);
    send.payload[242]
}

fn option(send: &Send, code: u8) -> Option<Vec<u8>> {
    let message = &send.payload;
    let mut at = 240;
    while message[at] != 255 {
        if message[at] == 0 {
            at += 1;
            continue;
        }
        let len = usize::from(message[at + 1]);
        if message[at] == code {
            return Some(message[at + 2..at + 2 + len].to_vec());
        }
        at += 2 + len;
    }
    None
}

fn reply(kind: u8, xid: u32, yiaddr: Ipv4Addr, lease: u32, mask: [u8; 4]) -> Vec<u8> {
    let mut out = vec![0; 236];
    out[..3].copy_from_slice(&[2, 1, 6]);
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[16..20].copy_from_slice(&yiaddr.octets());
    out[28..34].copy_from_slice(&MAC);
    out.extend_from_slice(&[99, 130, 83, 99, 53, 1, kind, 54, 4]);
    out.extend_from_slice(&SERVER.octets());
    out.extend_from_slice(&[1, 4]);
    out.extend_from_slice(&mask);
    out.extend_from_slice(&[3, 4, 198, 51, 100, 1, 6, 4, 192, 0, 2, 53, 51, 4]);
    out.extend_from_slice(&lease.to_be_bytes());
    out.push(255);
    out
}

/// Runs the client's timer; what it sent.
fn fire(client: &mut Client) -> (u64, Output) {
    let at = client.next_timer().expect("a timer");
    let mut out = Output::default();
    client.timeout(at, &mut out);
    (at, out)
}

/// A client bound to ADDRESS for a lease of `lease` seconds; when it was bound.
fn bound(lease: u32) -> (Client, u64) {
    let mut client = Client::new(MAC, 7, 0);
    let (at, out) = fire(&mut client);
    let discover = &out.sends[0];
    let mut out = Output::default();
    client.receive(
        at,
        &reply(
            kind::OFFER,
            xid(discover),
            ADDRESS,
            lease,
            [255, 255, 255, 0],
        ),
        &mut out,
    );
    let request = &out.sends[0];
    let mut out = Output::default();
    client.receive(
        at + 10,
        &reply(kind::ACK, xid(request), ADDRESS, lease, [255, 255, 255, 0]),
        &mut out,
    );
    assert_eq!(client.state(), State::Bound);
    (client, at + 10)
}

#[test]
fn it_discovers_after_one_to_ten_seconds_and_sends_again_with_backoff() {
    for seed in 0..20 {
        let mut client = Client::new(MAC, seed, 0);
        let first = client.next_timer().unwrap();
        assert!((1_000..=10_000).contains(&first), "{first}");
        let (_, out) = fire(&mut client);
        assert_eq!(out.sends.len(), 1);
        let discover = &out.sends[0];
        assert_eq!(kind_of(discover), kind::DISCOVER);
        assert_eq!(discover.to, To::Broadcast);
        assert_eq!(discover.from, Ipv4Addr::UNSPECIFIED);
        // 4, 8, 16, 32, 64, 64 s, each within a second.
        let mut at = first;
        for wait in [4_000, 8_000, 16_000, 32_000, 64_000, 64_000] {
            let next = client.next_timer().unwrap();
            assert!(next >= at + wait - 1_000 && next <= at + wait + 1_000);
            let (now, out) = fire(&mut client);
            assert_eq!(xid(&out.sends[0]), xid(discover), "the same exchange");
            at = now;
        }
    }
}

#[test]
fn an_offer_is_requested_and_an_ack_binds() {
    let mut client = Client::new(MAC, 1, 0);
    let (at, out) = fire(&mut client);
    let discover = out.sends[0].clone();
    // Another client's offer, or another exchange's, is not ours.
    let mut out = Output::default();
    client.receive(
        at,
        &reply(kind::OFFER, xid(&discover) ^ 1, ADDRESS, 3600, [255; 4]),
        &mut out,
    );
    assert!(out.sends.is_empty());
    client.receive(
        at,
        &reply(
            kind::OFFER,
            xid(&discover),
            ADDRESS,
            3600,
            [255, 255, 255, 0],
        ),
        &mut out,
    );
    assert_eq!(client.state(), State::Requesting);
    let request = &out.sends[0];
    assert_eq!(kind_of(request), kind::REQUEST);
    assert_eq!(request.to, To::Broadcast);
    assert_eq!(option(request, 50), Some(ADDRESS.octets().to_vec()));
    assert_eq!(option(request, 54), Some(SERVER.octets().to_vec()));
    let mut out = Output::default();
    client.receive(
        at,
        &reply(kind::ACK, xid(request), ADDRESS, 3600, [255, 255, 255, 0]),
        &mut out,
    );
    let lease = Lease {
        address: ADDRESS,
        prefix_len: 24,
        routers: vec![SERVER],
        dns: vec![Ipv4Addr::new(192, 0, 2, 53)],
        server: SERVER,
        lease_time: 3600,
        t1: 1800,
        t2: 3150,
    };
    assert_eq!(out.events, [Event::Bound(lease.clone())]);
    assert_eq!(client.lease(), Some(&lease));
    assert_eq!(client.next_timer(), Some(at + 1_800_000));
}

#[test]
fn it_renews_with_the_server_then_rebinds_then_gives_the_address_up() {
    let (mut client, bound_at) = bound(3600);
    let (at, out) = fire(&mut client);
    assert_eq!(at, bound_at + 1_800_000);
    assert_eq!(client.state(), State::Renewing);
    let renew = &out.sends[0];
    assert_eq!(kind_of(renew), kind::REQUEST);
    assert_eq!(renew.to, To::Server(SERVER));
    assert_eq!(renew.from, ADDRESS);
    assert_eq!(&renew.payload[12..16], &ADDRESS.octets());
    assert_eq!(option(renew, 50), None);
    assert_eq!(option(renew, 54), None);
    // Again after half the time to T2 (675 s), then down to 60 s, then T2.
    let mut last = at;
    while client.state() == State::Renewing {
        let next = client.next_timer().unwrap();
        assert!(next - last >= 60_000 || next == bound_at + 3_150_000);
        let (now, _) = fire(&mut client);
        last = now;
    }
    assert_eq!(last, bound_at + 3_150_000);
    assert_eq!(client.state(), State::Rebinding);
    while client.state() == State::Rebinding {
        let (now, out) = fire(&mut client);
        last = now;
        if client.state() == State::Rebinding {
            assert_eq!(out.sends[0].to, To::Broadcast);
            assert_eq!(out.sends[0].from, ADDRESS);
        } else {
            assert_eq!(out.events, [Event::Lost]);
        }
    }
    assert_eq!(last, bound_at + 3_600_000);
    assert_eq!(client.state(), State::Init);
    assert_eq!(client.lease(), None);
}

#[test]
fn an_ack_to_a_renewal_extends_the_lease() {
    let (mut client, _) = bound(3600);
    let (at, out) = fire(&mut client);
    let mut done = Output::default();
    client.receive(
        at + 5,
        &reply(
            kind::ACK,
            xid(&out.sends[0]),
            ADDRESS,
            7200,
            [255, 255, 255, 0],
        ),
        &mut done,
    );
    assert_eq!(client.state(), State::Bound);
    assert!(matches!(&done.events[..], [Event::Bound(l)] if l.lease_time == 7200));
    assert_eq!(client.next_timer(), Some(at + 5 + 3_600_000));
}

#[test]
fn a_nak_sends_the_client_back_to_init() {
    let (mut client, _) = bound(3600);
    let (at, out) = fire(&mut client);
    let mut done = Output::default();
    client.receive(
        at,
        &reply(
            kind::NAK,
            xid(&out.sends[0]),
            Ipv4Addr::UNSPECIFIED,
            0,
            [0; 4],
        ),
        &mut done,
    );
    assert_eq!(done.events, [Event::Lost]);
    assert_eq!(client.state(), State::Init);
    // Not at once: a server that keeps refusing gets no flood.
    let next = client.next_timer().unwrap();
    assert!((at + 1_000..=at + 10_000).contains(&next), "{next}");
    let (_, out) = fire(&mut client);
    assert_eq!(kind_of(&out.sends[0]), kind::DISCOVER);
}

#[test]
fn an_unanswered_request_goes_back_to_init() {
    let mut client = Client::new(MAC, 3, 0);
    let (at, out) = fire(&mut client);
    let mut done = Output::default();
    client.receive(
        at,
        &reply(kind::OFFER, xid(&out.sends[0]), ADDRESS, 3600, [255; 4]),
        &mut done,
    );
    for _ in 1..REQUEST_TRIES {
        let (_, out) = fire(&mut client);
        assert_eq!(kind_of(&out.sends[0]), kind::REQUEST);
    }
    let (_, out) = fire(&mut client);
    assert!(out.sends.is_empty());
    assert_eq!(client.state(), State::Init);
}

#[test]
fn an_address_a_host_cannot_have_is_declined() {
    let mut client = Client::new(MAC, 4, 0);
    let (at, out) = fire(&mut client);
    let broadcast = Ipv4Addr::new(198, 51, 100, 255);
    let mut done = Output::default();
    client.receive(
        at,
        &reply(
            kind::OFFER,
            xid(&out.sends[0]),
            broadcast,
            3600,
            [255, 255, 255, 0],
        ),
        &mut done,
    );
    let request = done.sends[0].clone();
    let mut done = Output::default();
    client.receive(
        at,
        &reply(
            kind::ACK,
            xid(&request),
            broadcast,
            3600,
            [255, 255, 255, 0],
        ),
        &mut done,
    );
    let decline = &done.sends[0];
    assert_eq!(kind_of(decline), kind::DECLINE);
    assert_eq!(option(decline, 50), Some(broadcast.octets().to_vec()));
    assert!(done.events.is_empty());
    // RFC 2131 section 3.1: at least 10 s before starting again.
    assert_eq!(client.next_timer(), Some(at + 10_000));
}

#[test]
fn release_gives_the_address_back_to_the_server() {
    let (mut client, at) = bound(3600);
    let mut out = Output::default();
    client.release(at + 1, &mut out);
    let release = &out.sends[0];
    assert_eq!(kind_of(release), kind::RELEASE);
    assert_eq!(release.to, To::Server(SERVER));
    assert_eq!(&release.payload[12..16], &ADDRESS.octets());
    assert_eq!(option(release, 54), Some(SERVER.octets().to_vec()));
    assert_eq!(out.events, [Event::Lost]);
    assert_eq!(client.next_timer(), None);
}

#[test]
fn an_infinite_lease_is_never_renewed() {
    let (client, _) = bound(u32::MAX);
    assert_eq!(client.next_timer(), None);
}

/// A server's reply with `options` (code, value) after the message type.
fn reply_with(kind: u8, xid: u32, chaddr: [u8; 6], options: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = vec![0; 236];
    out[..3].copy_from_slice(&[2, 1, 6]);
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[16..20].copy_from_slice(&ADDRESS.octets());
    out[28..34].copy_from_slice(&chaddr);
    out.extend_from_slice(&[99, 130, 83, 99, 53, 1, kind]);
    for (code, value) in options {
        out.extend_from_slice(&[*code, value.len() as u8]);
        out.extend_from_slice(value);
    }
    out.push(255);
    out
}

/// The fields of RFC 2131 table 5 that a client always sets to 0: hops, yiaddr,
/// siaddr and giaddr; and chaddr.
fn zero_fields(send: &Send) {
    assert_eq!(send.payload[3], 0, "hops");
    assert_eq!(&send.payload[16..28], &[0; 12], "yiaddr, siaddr, giaddr");
    assert_eq!(&send.payload[28..34], &MAC, "chaddr");
}

fn secs(send: &Send) -> u16 {
    u16::from_be_bytes([send.payload[8], send.payload[9]])
}

#[test]
fn a_discover_follows_table_5() {
    // RFC 2131 table 5, DHCPDISCOVER: ciaddr 0, no server identifier.
    let mut client = Client::new(MAC, 11, 0);
    let (_, out) = fire(&mut client);
    let discover = &out.sends[0];
    zero_fields(discover);
    assert_eq!(&discover.payload[12..16], &[0; 4], "ciaddr");
    assert_eq!(secs(discover), 0, "the first of the exchange");
    assert_eq!(option(discover, 54), None);
    // RFC 2132 section 9.10: the maximum message size is at least 576.
    let size = option(discover, 57).unwrap();
    assert!(u16::from_be_bytes([size[0], size[1]]) >= 576);
}

#[test]
fn a_request_in_selecting_repeats_the_discovers_xid_and_secs() {
    // RFC 2131 section 4.4.1: the DHCPREQUEST "MUST use the same value in the DHCP
    // message header's 'secs' field ... as the original DHCPDISCOVER". Table 5:
    // ciaddr 0, requested address and server identifier.
    let mut client = Client::new(MAC, 12, 0);
    fire(&mut client);
    fire(&mut client);
    let (at, out) = fire(&mut client);
    let discover = out.sends[0].clone();
    assert!(secs(&discover) >= 10, "sent again: {}", secs(&discover));
    let mut out = Output::default();
    client.receive(
        at + 3_000,
        &reply(kind::OFFER, xid(&discover), ADDRESS, 3600, [255; 4]),
        &mut out,
    );
    let request = &out.sends[0];
    assert_eq!(xid(request), xid(&discover));
    assert_eq!(secs(request), secs(&discover));
    assert_eq!(&request.payload[10..12], &[0x80, 0], "BROADCAST flag");
    assert_eq!(&request.payload[12..16], &[0; 4], "ciaddr");
    zero_fields(request);
    // Sent again (section 4.1) with the same secs.
    let (_, again) = fire(&mut client);
    assert_eq!(secs(&again.sends[0]), secs(&discover));
}

#[test]
fn requests_in_requesting_are_sent_again_as_section_4_1_says() {
    // RFC 2131 section 4.1: 4 s, then 8 s, ..., each within -1 to +1 s.
    for seed in 0..10 {
        let mut client = Client::new(MAC, seed, 0);
        let (at, out) = fire(&mut client);
        let mut done = Output::default();
        client.receive(
            at,
            &reply(kind::OFFER, xid(&out.sends[0]), ADDRESS, 3600, [255; 4]),
            &mut done,
        );
        let mut last = at;
        for wait in [4_000, 8_000, 16_000] {
            let next = client.next_timer().unwrap();
            assert!(
                (last + wait - 1_000..=last + wait + 1_000).contains(&next),
                "{}",
                next - last
            );
            let (now, out) = fire(&mut client);
            assert_eq!(kind_of(&out.sends[0]), kind::REQUEST);
            last = now;
        }
    }
}

#[test]
fn renewing_and_rebinding_wait_half_the_time_left_but_at_least_60_s() {
    // RFC 2131 section 4.4.5: in RENEWING, again after one-half of the time left
    // until T2, in REBINDING one-half of the time left in the lease, down to 60 s.
    let (mut client, bound_at) = bound(3600);
    let t2 = bound_at + 3_150_000;
    let end = bound_at + 3_600_000;
    let (mut now, _) = fire(&mut client);
    while client.state() == State::Renewing {
        let next = client.next_timer().unwrap();
        assert_eq!(next, t2.min(now + ((t2 - now) / 2).max(60_000)));
        now = fire(&mut client).0;
    }
    assert_eq!(now, t2);
    while client.state() == State::Rebinding {
        let next = client.next_timer().unwrap();
        assert_eq!(next, end.min(now + ((end - now) / 2).max(60_000)));
        now = fire(&mut client).0;
    }
    assert_eq!(now, end);
}

#[test]
fn a_rebinding_request_carries_ciaddr_and_no_server_or_requested_address() {
    // RFC 2131 table 5, DHCPREQUEST in REBINDING: ciaddr is the client's address,
    // options 50 and 54 MUST NOT be sent; it is broadcast (section 4.4.5).
    let (mut client, _) = bound(3600);
    while client.state() != State::Rebinding {
        fire(&mut client);
    }
    let (_, out) = fire(&mut client);
    let rebind = &out.sends[0];
    assert_eq!(kind_of(rebind), kind::REQUEST);
    assert_eq!(rebind.to, To::Broadcast);
    assert_eq!(&rebind.payload[12..16], &ADDRESS.octets());
    assert_eq!(&rebind.payload[10..12], &[0, 0], "no BROADCAST flag");
    assert_eq!(option(rebind, 50), None);
    assert_eq!(option(rebind, 54), None);
    zero_fields(rebind);
}

#[test]
fn t1_and_t2_from_the_server_are_used() {
    // RFC 2132 sections 9.11 and 9.12: the renewal (58) and rebinding (59) times.
    let mut client = Client::new(MAC, 13, 0);
    let (at, out) = fire(&mut client);
    let options: &[(u8, &[u8])] = &[
        (54, &SERVER.octets()),
        (1, &[255, 255, 255, 0]),
        (51, &3600u32.to_be_bytes()),
        (58, &1000u32.to_be_bytes()),
        (59, &2000u32.to_be_bytes()),
    ];
    let mut next = Output::default();
    client.receive(
        at,
        &reply_with(kind::OFFER, xid(&out.sends[0]), MAC, options),
        &mut next,
    );
    let mut done = Output::default();
    client.receive(
        at,
        &reply_with(kind::ACK, xid(&next.sends[0]), MAC, options),
        &mut done,
    );
    let lease = client.lease().unwrap();
    assert_eq!((lease.t1, lease.t2), (1000, 2000));
    assert_eq!(client.next_timer(), Some(at + 1_000_000));
}

#[test]
fn a_nak_in_requesting_or_rebinding_goes_back_to_init() {
    // RFC 2131 section 4.4 (figure 5): DHCPNAK in REQUESTING, RENEWING and
    // REBINDING goes to INIT; with an address, the address is given up.
    let mut client = Client::new(MAC, 14, 0);
    let (at, out) = fire(&mut client);
    let mut next = Output::default();
    client.receive(
        at,
        &reply(kind::OFFER, xid(&out.sends[0]), ADDRESS, 3600, [255; 4]),
        &mut next,
    );
    let mut done = Output::default();
    client.receive(
        at,
        &reply(
            kind::NAK,
            xid(&next.sends[0]),
            Ipv4Addr::UNSPECIFIED,
            0,
            [0; 4],
        ),
        &mut done,
    );
    assert_eq!(client.state(), State::Init);
    assert!(done.events.is_empty(), "no address was held");

    let (mut client, _) = bound(3600);
    while client.state() != State::Rebinding {
        fire(&mut client);
    }
    let (at, out) = fire(&mut client);
    let mut done = Output::default();
    client.receive(
        at,
        &reply(
            kind::NAK,
            xid(&out.sends[0]),
            Ipv4Addr::UNSPECIFIED,
            0,
            [0; 4],
        ),
        &mut done,
    );
    assert_eq!(done.events, [Event::Lost]);
    assert_eq!(client.state(), State::Init);
}

#[test]
fn replies_for_another_client_or_from_another_server_are_not_taken() {
    // RFC 2131 section 4.4.1: the reply matches the client's xid and chaddr; the
    // DHCPACK in REQUESTING comes from the server the client chose (option 54).
    let mut client = Client::new(MAC, 15, 0);
    let (at, out) = fire(&mut client);
    let xid = xid(&out.sends[0]);
    let offer: &[(u8, &[u8])] = &[(54, &SERVER.octets()), (51, &3600u32.to_be_bytes())];
    let mut next = Output::default();
    client.receive(
        at,
        &reply_with(kind::OFFER, xid, [2, 0, 0, 0, 0, 9], offer),
        &mut next,
    );
    assert!(next.sends.is_empty());
    assert_eq!(client.state(), State::Selecting);
    client.receive(at, &reply_with(kind::OFFER, xid, MAC, offer), &mut next);
    assert_eq!(client.state(), State::Requesting);
    let other: &[(u8, &[u8])] = &[(54, &[198, 51, 100, 2]), (51, &3600u32.to_be_bytes())];
    let mut done = Output::default();
    client.receive(at, &reply_with(kind::ACK, xid, MAC, other), &mut done);
    assert_eq!(client.state(), State::Requesting);
    assert!(done.events.is_empty());
}

#[test]
fn decline_and_release_follow_table_5() {
    // RFC 2131 table 5: DHCPDECLINE has ciaddr 0, secs 0, options 50 and 54 and no
    // parameter list (55) or maximum size (57); DHCPRELEASE has ciaddr, secs 0,
    // option 54 and no 50.
    let mut client = Client::new(MAC, 16, 0);
    let (at, out) = fire(&mut client);
    let network = Ipv4Addr::new(198, 51, 100, 0);
    let mut done = Output::default();
    client.receive(
        at + 5_000,
        &reply(
            kind::OFFER,
            xid(&out.sends[0]),
            network,
            3600,
            [255, 255, 255, 0],
        ),
        &mut done,
    );
    let request = done.sends[0].clone();
    let mut done = Output::default();
    client.receive(
        at + 6_000,
        &reply(kind::ACK, xid(&request), network, 3600, [255, 255, 255, 0]),
        &mut done,
    );
    let decline = &done.sends[0];
    assert_eq!(kind_of(decline), kind::DECLINE);
    assert_eq!(secs(decline), 0);
    assert_eq!(&decline.payload[10..16], &[0; 6], "flags and ciaddr");
    assert_eq!(option(decline, 50), Some(network.octets().to_vec()));
    assert_eq!(option(decline, 54), Some(SERVER.octets().to_vec()));
    assert_eq!(option(decline, 55), None);
    assert_eq!(option(decline, 57), None);
    zero_fields(decline);

    let (mut client, at) = bound(3600);
    let mut out = Output::default();
    client.release(at + 5_000, &mut out);
    let release = &out.sends[0];
    assert_eq!(secs(release), 0);
    assert_eq!(option(release, 50), None);
    assert_eq!(option(release, 55), None);
    assert_eq!(option(release, 57), None);
    zero_fields(release);
}

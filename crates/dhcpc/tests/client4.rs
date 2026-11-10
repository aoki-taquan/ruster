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

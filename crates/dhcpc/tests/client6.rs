//! DHCPv6 messages and the client's states (RFC 8415 sections 15 and 18.2).

use std::net::Ipv6Addr;

use ruster_dhcpc::client6::{Client, Event, Output, State, Want, REQUEST_TRIES};
use ruster_dhcpc::dhcp6::{duid, kind, status, IaAddress, IaPrefix, Reply, Request, IAID};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const SERVER_ID: &[u8] = &[0, 3, 0, 1, 2, 0, 0, 0, 0, 0x99];
const BOTH: Want = Want {
    address: true,
    prefix: true,
};
const PD: Want = Want {
    address: false,
    prefix: true,
};

fn put(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// The options of a client message, as (code, value).
fn options(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 4;
    while at < message.len() {
        let code = u16::from_be_bytes([message[at], message[at + 1]]);
        let len = usize::from(u16::from_be_bytes([message[at + 2], message[at + 3]]));
        out.push((code, message[at + 4..at + 4 + len].to_vec()));
        at += 4 + len;
    }
    out
}

fn has(message: &[u8], code: u16) -> Option<Vec<u8>> {
    options(message)
        .into_iter()
        .find(|(c, _)| *c == code)
        .map(|(_, v)| v)
}

fn xid(message: &[u8]) -> u32 {
    u32::from_be_bytes([0, message[1], message[2], message[3]])
}

struct Server {
    t1: u32,
    t2: u32,
    preferred: u32,
    valid: u32,
    ia_status: Option<u16>,
}

const SERVER: Server = Server {
    t1: 1800,
    t2: 2880,
    preferred: 3600,
    valid: 7200,
    ia_status: None,
};

fn reply(kind: u8, to: &[u8], server: &Server) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&to[1..4]);
    put(&mut out, 1, &duid(MAC));
    put(&mut out, 2, SERVER_ID);
    put(
        &mut out,
        23,
        &"2001:db8::53".parse::<Ipv6Addr>().unwrap().octets(),
    );
    let ia = |held: Vec<u8>, held_code: u16| {
        let mut value = IAID.to_be_bytes().to_vec();
        value.extend_from_slice(&server.t1.to_be_bytes());
        value.extend_from_slice(&server.t2.to_be_bytes());
        match server.ia_status {
            Some(code) => put(&mut value, 13, &code.to_be_bytes()),
            None => put(&mut value, held_code, &held),
        }
        value
    };
    let mut address = "2001:db8:ff::20"
        .parse::<Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    address.extend_from_slice(&server.preferred.to_be_bytes());
    address.extend_from_slice(&server.valid.to_be_bytes());
    put(&mut out, 3, &ia(address, 5));
    let mut prefix = server.preferred.to_be_bytes().to_vec();
    prefix.extend_from_slice(&server.valid.to_be_bytes());
    prefix.push(56);
    // A host bit set: the client clears it.
    prefix.extend_from_slice(&"2001:db8:12:3401::".parse::<Ipv6Addr>().unwrap().octets());
    put(&mut out, 25, &ia(prefix, 26));
    out
}

fn fire(client: &mut Client) -> (u64, Output) {
    let at = client.next_timer().expect("a timer");
    let mut out = Output::default();
    client.timeout(at, &mut out);
    (at, out)
}

fn bound(want: Want, server: &Server) -> (Client, u64) {
    let mut client = Client::new(MAC, want, 5, 0);
    let (at, out) = fire(&mut client);
    let mut next = Output::default();
    client.receive(
        at,
        &reply(kind::ADVERTISE, &out.sends[0], server),
        &mut next,
    );
    let mut done = Output::default();
    client.receive(
        at + 5,
        &reply(kind::REPLY, &next.sends[0], server),
        &mut done,
    );
    assert_eq!(client.state(), State::Bound);
    (client, at + 5)
}

#[test]
fn a_solicit_asks_for_a_prefix_and_dns_servers() {
    let mut client = Client::new(MAC, PD, 1, 0);
    assert!(client.next_timer().unwrap() <= 1_000);
    let (_, out) = fire(&mut client);
    let solicit = &out.sends[0];
    assert_eq!(solicit[0], kind::SOLICIT);
    assert_eq!(has(solicit, 1), Some(vec![0, 3, 0, 1, 2, 0, 0, 0, 0, 2]));
    assert_eq!(has(solicit, 8), Some(vec![0, 0]));
    assert_eq!(has(solicit, 6), Some(vec![0, 23]));
    assert_eq!(has(solicit, 25).unwrap().len(), 12);
    assert_eq!(has(solicit, 3), None, "no IA_NA unless asked");
    assert_eq!(has(solicit, 2), None);
}

#[test]
fn solicits_are_sent_again_as_section_15_says() {
    let mut client = Client::new(MAC, PD, 2, 0);
    let (at, out) = fire(&mut client);
    let first = xid(&out.sends[0]);
    let start = at;
    // RT starts at 1 s plus up to 0.1 s, then about doubles.
    let next = client.next_timer().unwrap();
    assert!((at + 1_000..=at + 1_100).contains(&next), "{}", next - at);
    let mut rt = next - at;
    for _ in 0..20 {
        let (now, out) = fire(&mut client);
        assert_eq!(xid(&out.sends[0]), first);
        let elapsed = u16::from_be_bytes(has(&out.sends[0], 8).unwrap().try_into().unwrap());
        assert_eq!(u64::from(elapsed), ((now - start) / 10).min(0xffff));
        let wait = client.next_timer().unwrap() - now;
        assert!(wait >= rt * 19 / 10 || wait >= 3_240_000, "{rt} {wait}");
        assert!(wait <= 3_960_000);
        rt = wait;
    }
}

#[test]
fn an_advertise_is_requested_and_the_reply_binds() {
    let mut client = Client::new(MAC, BOTH, 3, 0);
    let (at, out) = fire(&mut client);
    let solicit = out.sends[0].clone();
    // Another transaction's, or another client's, is not ours.
    let mut other = reply(kind::ADVERTISE, &solicit, &SERVER);
    other[3] ^= 1;
    let mut next = Output::default();
    client.receive(at, &other, &mut next);
    assert!(next.sends.is_empty());
    client.receive(at, &reply(kind::ADVERTISE, &solicit, &SERVER), &mut next);
    let request = &next.sends[0];
    assert_eq!(request[0], kind::REQUEST);
    assert_eq!(has(request, 2), Some(SERVER_ID.to_vec()));
    let ia_pd = has(request, 25).unwrap();
    assert_eq!(&ia_pd[..12], &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(ia_pd.len() > 12, "holds the prefix it asks for");
    let mut done = Output::default();
    client.receive(at, &reply(kind::REPLY, request, &SERVER), &mut done);
    let [Event::Bound(lease)] = &done.events[..] else {
        panic!("{:?}", done.events)
    };
    assert_eq!(
        lease.prefix,
        Some(IaPrefix {
            prefix: "2001:db8:12:3400::".parse().unwrap(),
            len: 56,
            preferred: 3600,
            valid: 7200,
        })
    );
    assert_eq!(
        lease.address,
        Some(IaAddress {
            address: "2001:db8:ff::20".parse().unwrap(),
            preferred: 3600,
            valid: 7200,
        })
    );
    assert_eq!(lease.dns, ["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
    assert_eq!((lease.t1, lease.t2), (1800, 2880));
    assert_eq!(client.next_timer(), Some(at + 1_800_000));
}

#[test]
fn an_advertise_without_a_prefix_is_not_taken() {
    let mut client = Client::new(MAC, PD, 4, 0);
    let (at, out) = fire(&mut client);
    let no_prefix = Server {
        ia_status: Some(status::NO_PREFIX_AVAIL),
        ..SERVER
    };
    let mut next = Output::default();
    client.receive(
        at,
        &reply(kind::ADVERTISE, &out.sends[0], &no_prefix),
        &mut next,
    );
    assert!(next.sends.is_empty());
    assert_eq!(client.state(), State::Soliciting);
}

#[test]
fn it_renews_then_rebinds_then_gives_the_lease_up() {
    let (mut client, bound_at) = bound(PD, &SERVER);
    let (at, out) = fire(&mut client);
    assert_eq!(at, bound_at + 1_800_000);
    let renew = &out.sends[0];
    assert_eq!(renew[0], kind::RENEW);
    assert_eq!(has(renew, 2), Some(SERVER_ID.to_vec()));
    let mut last = at;
    while client.state() == State::Renewing {
        let (now, _) = fire(&mut client);
        last = now;
    }
    assert_eq!(last, bound_at + 2_880_000, "Rebind at T2");
    assert_eq!(client.state(), State::Rebinding);
    let mut lost = false;
    while client.state() == State::Rebinding {
        let (now, out) = fire(&mut client);
        last = now;
        if client.state() == State::Rebinding {
            assert_eq!(out.sends[0][0], kind::REBIND);
            assert_eq!(has(&out.sends[0], 2), None);
        } else {
            lost = out.events == [Event::Lost];
        }
    }
    assert!(lost);
    assert_eq!(
        last,
        bound_at + 7_200_000,
        "at the end of the valid lifetime"
    );
}

#[test]
fn a_reply_to_a_renew_extends_or_ends_the_lease() {
    let (mut client, _) = bound(PD, &SERVER);
    let (at, out) = fire(&mut client);
    let mut done = Output::default();
    client.receive(at, &reply(kind::REPLY, &out.sends[0], &SERVER), &mut done);
    assert!(matches!(&done.events[..], [Event::Bound(_)]));
    assert_eq!(client.next_timer(), Some(at + 1_800_000));
    // NoBinding: asked for again with a Request.
    let (at, out) = fire(&mut client);
    let no_binding = Server {
        ia_status: Some(status::NO_BINDING),
        ..SERVER
    };
    let mut done = Output::default();
    client.receive(
        at,
        &reply(kind::REPLY, &out.sends[0], &no_binding),
        &mut done,
    );
    assert_eq!(client.state(), State::Requesting);
    assert_eq!(done.sends[0][0], kind::REQUEST);
    // Lifetimes of 0: the prefix is gone.
    let (mut client, _) = bound(PD, &SERVER);
    let (at, out) = fire(&mut client);
    let gone = Server {
        preferred: 0,
        valid: 0,
        ..SERVER
    };
    let mut done = Output::default();
    client.receive(at, &reply(kind::REPLY, &out.sends[0], &gone), &mut done);
    assert_eq!(done.events, [Event::Lost]);
}

#[test]
fn zero_t1_and_t2_are_the_clients_to_choose() {
    let (client, at) = bound(
        PD,
        &Server {
            t1: 0,
            t2: 0,
            ..SERVER
        },
    );
    let lease = client.lease().unwrap();
    assert_eq!((lease.t1, lease.t2), (1800, 2880));
    assert_eq!(client.next_timer(), Some(at + 1_800_000));
}

#[test]
fn unanswered_requests_go_back_to_solicit() {
    let mut client = Client::new(MAC, PD, 6, 0);
    let (at, out) = fire(&mut client);
    let mut next = Output::default();
    client.receive(
        at,
        &reply(kind::ADVERTISE, &out.sends[0], &SERVER),
        &mut next,
    );
    for _ in 1..REQUEST_TRIES {
        let (_, out) = fire(&mut client);
        assert_eq!(out.sends[0][0], kind::REQUEST);
    }
    let (_, out) = fire(&mut client);
    assert!(out.sends.is_empty());
    assert_eq!(client.state(), State::Init);
}

#[test]
fn release_gives_the_lease_back() {
    let (mut client, at) = bound(BOTH, &SERVER);
    let mut out = Output::default();
    client.release(at, &mut out);
    let release = &out.sends[0];
    assert_eq!(release[0], kind::RELEASE);
    assert_eq!(has(release, 2), Some(SERVER_ID.to_vec()));
    assert!(has(release, 25).unwrap().len() > 12);
    assert!(has(release, 3).unwrap().len() > 12);
    assert_eq!(out.events, [Event::Lost]);
    assert_eq!(client.next_timer(), None);
}

#[test]
fn malformed_replies_are_not_read() {
    let to = Request {
        kind: kind::SOLICIT,
        xid: 7,
        elapsed: 0,
        client_id: &duid(MAC),
        server_id: None,
        ia_na: None,
        ia_pd: Some(None),
    }
    .encode();
    let good = reply(kind::REPLY, &to, &SERVER);
    assert!(Reply::parse(&good).is_some());
    for len in 0..good.len() {
        // Cut anywhere but at an option's end, it is refused; at an option's end
        // it is read without what follows. Either way, no panic.
        let _ = Reply::parse(&good[..len]);
    }
    assert!(Reply::parse(&good[..good.len() - 1]).is_none());
    assert!(Reply::parse(&to).is_none(), "a Solicit is not a reply");
    // A prefix length above 128 is not a prefix.
    let mut bad = good.clone();
    let at = bad.len() - 17;
    bad[at] = 200;
    assert_eq!(Reply::parse(&bad).unwrap().ia_pd.unwrap().lease, None);
}

#[test]
fn a_preferred_lifetime_of_0_does_not_make_it_renew_without_pause() {
    let (client, at) = bound(
        PD,
        &Server {
            t1: 0,
            t2: 0,
            preferred: 0,
            ..SERVER
        },
    );
    assert!(client.next_timer().unwrap() >= at + 10_000);
}

#[test]
fn a_lease_held_while_asking_again_still_ends() {
    let (mut client, bound_at) = bound(PD, &SERVER);
    let (at, out) = fire(&mut client);
    let no_binding = Server {
        ia_status: Some(status::NO_BINDING),
        ..SERVER
    };
    let mut done = Output::default();
    client.receive(
        at,
        &reply(kind::REPLY, &out.sends[0], &no_binding),
        &mut done,
    );
    let mut lost = false;
    for _ in 0..100 {
        let (now, out) = fire(&mut client);
        if out.events == [Event::Lost] {
            lost = true;
            assert!(now <= bound_at + 7_200_000);
            break;
        }
    }
    assert!(lost);
    assert!(client.lease().is_none());
}

#[test]
fn a_prefix_being_taken_away_is_passed_over_for_the_next() {
    let mut client = Client::new(MAC, PD, 8, 0);
    let (at, out) = fire(&mut client);
    let mut advertise = reply(kind::ADVERTISE, &out.sends[0], &SERVER);
    // Another IA Prefix with lifetimes 0 before the good one in the IA_PD.
    let ia_pd = advertise.len() - (4 + 12 + 4 + 25);
    let mut old = vec![0, 26, 0, 25];
    old.extend_from_slice(&[0; 8]);
    old.push(48);
    old.extend_from_slice(&"2001:db8:99::".parse::<Ipv6Addr>().unwrap().octets());
    let at_options = ia_pd + 4 + 12;
    advertise.splice(at_options..at_options, old);
    let len = u16::from_be_bytes([advertise[ia_pd + 2], advertise[ia_pd + 3]]) + 29;
    advertise[ia_pd + 2..ia_pd + 4].copy_from_slice(&len.to_be_bytes());
    let parsed = Reply::parse(&advertise).unwrap();
    assert_eq!(parsed.ia_pd.unwrap().lease.unwrap().len, 56);
    let mut next = Output::default();
    client.receive(at, &advertise, &mut next);
    assert_eq!(client.state(), State::Requesting);
}

#[test]
fn a_server_that_keeps_failing_gets_ever_longer_waits() {
    let mut client = Client::new(MAC, PD, 9, 0);
    let no_prefix = Server {
        ia_status: Some(status::NO_PREFIX_AVAIL),
        ..SERVER
    };
    let mut waits = Vec::new();
    for _ in 0..6 {
        let (at, out) = fire(&mut client);
        let mut next = Output::default();
        client.receive(
            at,
            &reply(kind::ADVERTISE, &out.sends[0], &SERVER),
            &mut next,
        );
        let mut done = Output::default();
        client.receive(
            at,
            &reply(kind::REPLY, &next.sends[0], &no_prefix),
            &mut done,
        );
        assert_eq!(client.state(), State::Init);
        waits.push(client.next_timer().unwrap() - at);
    }
    assert!(waits[5] >= 28_000, "{waits:?}");
}

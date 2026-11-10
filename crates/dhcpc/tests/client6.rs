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
    assert_eq!(has(solicit, 6), Some(vec![0, 82, 0, 23]));
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

/// `message` with the top-level option `code` added.
fn with(mut message: Vec<u8>, code: u16, value: &[u8]) -> Vec<u8> {
    put(&mut message, code, value);
    message
}

/// `message` without its top-level options `code`.
fn without(message: &[u8], code: u16) -> Vec<u8> {
    let mut out = message[..4].to_vec();
    for (c, value) in options(message) {
        if c != code {
            put(&mut out, c, &value);
        }
    }
    out
}

/// A client in REQUESTING; the Request it sent.
fn requesting(seed: u64) -> (Client, u64, Vec<u8>) {
    let mut client = Client::new(MAC, PD, seed, 0);
    let (at, out) = fire(&mut client);
    let mut next = Output::default();
    client.receive(
        at,
        &reply(kind::ADVERTISE, &out.sends[0], &SERVER),
        &mut next,
    );
    assert_eq!(client.state(), State::Requesting);
    (client, at, next.sends[0].clone())
}

/// Checks the retransmissions of RFC 8415 section 15 from the first RT on: each
/// RT within 0.1 of `irt`, then of twice the last, and past `mrt` within 0.1 of
/// it. Gives the times sent.
fn retransmits(client: &mut Client, mut now: u64, irt: u64, mrt: u64, count: usize) -> Vec<u64> {
    let mut sent = Vec::new();
    let mut rt = client.next_timer().unwrap() - now;
    assert!(
        (irt - irt / 10..=irt + irt / 10).contains(&rt),
        "first RT {rt}"
    );
    for _ in 0..count {
        now = fire(client).0;
        sent.push(now);
        let next = client.next_timer().unwrap() - now;
        let doubled = 2 * rt - rt / 10..=2 * rt + rt / 10;
        let capped = mrt - mrt / 10..=mrt + mrt / 10;
        assert!(
            doubled.contains(&next) && next <= mrt + mrt / 10 || capped.contains(&next),
            "{rt} then {next}"
        );
        rt = next;
    }
    sent
}

#[test]
fn the_first_solicits_rt_is_strictly_above_irt() {
    // RFC 8415 section 15: for the first Solicit, RAND is strictly greater than 0,
    // so RT is above IRT (1 s) and at most 1.1 s.
    for seed in 0..200 {
        let mut client = Client::new(MAC, PD, seed, 0);
        let (at, _) = fire(&mut client);
        let rt = client.next_timer().unwrap() - at;
        assert!(rt > 1_000 && rt <= 1_100, "{rt}");
    }
}

#[test]
fn requests_are_sent_again_with_req_timeout_and_req_max_rt() {
    // RFC 8415 section 7.6 and 18.2.2: REQ_TIMEOUT 1 s, REQ_MAX_RT 30 s,
    // REQ_MAX_RC 10. Section 21.9: the Elapsed Time of a new exchange starts at 0.
    assert_eq!(REQUEST_TRIES, 10);
    let (mut client, at, request) = requesting(20);
    assert_eq!(has(&request, 8), Some(vec![0, 0]));
    assert_eq!(has(&request, 1), Some(duid(MAC)));
    assert_eq!(has(&request, 2), Some(SERVER_ID.to_vec()));
    let sent = retransmits(&mut client, at, 1_000, 30_000, 8);
    // 1, 2, 4, 8, 16 s, then 30 s.
    assert!(sent[7] - sent[6] >= 27_000);
}

#[test]
fn renews_and_rebinds_are_sent_again_with_their_timeouts() {
    // RFC 8415 section 7.6, 18.2.4 and 18.2.5: REN_TIMEOUT and REB_TIMEOUT 10 s,
    // REN_MAX_RT and REB_MAX_RT 600 s; Renew until T2 (MRD), Rebind until the
    // valid lifetimes end.
    let long = Server {
        t1: 10_000,
        t2: 20_000,
        preferred: 30_000,
        valid: 40_000,
        ia_status: None,
    };
    let (mut client, bound_at) = bound(PD, &long);
    let (at, out) = fire(&mut client);
    assert_eq!(at, bound_at + 10_000_000);
    let renew = &out.sends[0];
    assert_eq!(has(renew, 8), Some(vec![0, 0]));
    assert_eq!(has(renew, 2), Some(SERVER_ID.to_vec()));
    let sent = retransmits(&mut client, at, 10_000, 600_000, 8);
    assert!(sent.iter().all(|t| *t < bound_at + 20_000_000));
    while client.state() == State::Renewing {
        fire(&mut client);
    }
    let rebind_at = bound_at + 20_000_000;
    let sent = retransmits(&mut client, rebind_at, 10_000, 600_000, 8);
    assert!(sent.iter().all(|t| *t < bound_at + 40_000_000));
}

#[test]
fn every_option_request_asks_for_sol_max_rt() {
    // RFC 8415 section 21.24: "A DHCP client MUST include the SOL_MAX_RT option
    // code in any Option Request option it sends."
    let mut client = Client::new(MAC, PD, 21, 0);
    let (at, out) = fire(&mut client);
    let mut sent = vec![out.sends[0].clone()];
    let mut next = Output::default();
    client.receive(
        at,
        &reply(kind::ADVERTISE, &out.sends[0], &SERVER),
        &mut next,
    );
    sent.push(next.sends[0].clone());
    let mut done = Output::default();
    client.receive(at, &reply(kind::REPLY, &next.sends[0], &SERVER), &mut done);
    while client.state() != State::Rebinding {
        sent.push(fire(&mut client).1.sends[0].clone());
    }
    sent.push(fire(&mut client).1.sends[0].clone());
    let kinds: Vec<u8> = sent.iter().map(|m| m[0]).collect();
    for wanted in [kind::SOLICIT, kind::REQUEST, kind::RENEW, kind::REBIND] {
        assert!(kinds.contains(&wanted), "{kinds:?}");
    }
    for message in &sent {
        let oro = has(message, 6).unwrap();
        assert!(oro.chunks(2).any(|c| c == [0, 82]), "{}", message[0]);
    }
}

#[test]
fn a_sol_max_rt_option_becomes_solicits_mrt() {
    // RFC 8415 section 18.2.9: the client takes SOL_MAX_RT (section 21.24, 60 to
    // 86400 s) even from an Advertise it drops for its status; a value out of
    // that range is ignored.
    let mut client = Client::new(MAC, PD, 22, 0);
    let (at, out) = fire(&mut client);
    let mut advertise = reply(kind::ADVERTISE, &out.sends[0], &SERVER);
    advertise = with(advertise, 13, &status::NO_ADDRS_AVAIL.to_be_bytes());
    advertise = with(advertise, 82, &59u32.to_be_bytes());
    let mut next = Output::default();
    client.receive(at, &advertise, &mut next);
    assert!(next.sends.is_empty());
    let mut advertise = reply(kind::ADVERTISE, &out.sends[0], &SERVER);
    advertise = with(advertise, 13, &status::NO_ADDRS_AVAIL.to_be_bytes());
    advertise = with(advertise, 82, &120u32.to_be_bytes());
    client.receive(at, &advertise, &mut next);
    assert!(
        next.sends.is_empty(),
        "a failure status drops the Advertise"
    );
    assert_eq!(client.state(), State::Soliciting);
    let mut most = 0;
    for _ in 0..12 {
        let now = fire(&mut client).0;
        most = most.max(client.next_timer().unwrap() - now);
    }
    assert!((108_000..=132_000).contains(&most), "{most}");
}

#[test]
fn messages_without_the_right_identifiers_are_dropped() {
    // RFC 8415 section 16.3 and 16.10: an Advertise or Reply without a Server
    // Identifier, or without the client's Client Identifier, is discarded; the
    // Reply to a Request comes from the server it was sent to.
    let mut client = Client::new(MAC, PD, 23, 0);
    let (at, out) = fire(&mut client);
    let good = reply(kind::ADVERTISE, &out.sends[0], &SERVER);
    let mut other_client = good.clone();
    let id = other_client
        .windows(10)
        .position(|w| w == duid(MAC).as_slice())
        .unwrap();
    other_client[id + 9] ^= 1;
    for bad in [without(&good, 2), without(&good, 1), other_client] {
        let mut next = Output::default();
        client.receive(at, &bad, &mut next);
        assert!(next.sends.is_empty());
        assert_eq!(client.state(), State::Soliciting);
    }
    let (mut client, at, request) = requesting(24);
    let mut other_server = without(&reply(kind::REPLY, &request, &SERVER), 2);
    other_server = with(other_server, 2, &[0, 3, 0, 1, 2, 0, 0, 0, 0, 0x98]);
    let mut done = Output::default();
    client.receive(at, &other_server, &mut done);
    assert_eq!(client.state(), State::Requesting);
    assert!(done.events.is_empty());
}

#[test]
fn the_ia_pd_asked_for_has_the_section_21_21_layout() {
    // RFC 8415 section 21.21: IA_PD is IAID, T1, T2 (the client sends 0) and its
    // options; section 21.22: IA Prefix (26) of length 25 is preferred and valid
    // lifetimes (0 from a client), prefix length and the prefix.
    let (_, _, request) = requesting(25);
    let ia_pd = has(&request, 25).unwrap();
    let mut expected = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 0, 25];
    expected.extend_from_slice(&[0; 8]);
    expected.push(56);
    expected.extend_from_slice(&"2001:db8:12:3400::".parse::<Ipv6Addr>().unwrap().octets());
    assert_eq!(ia_pd, expected);
}

#[test]
fn a_prefix_with_preferred_above_valid_is_dropped() {
    // RFC 8415 section 21.22: "The client MUST discard any prefixes for which the
    // preferred lifetime is greater than the valid lifetime."
    let mut client = Client::new(MAC, PD, 26, 0);
    let (at, out) = fire(&mut client);
    let bad = Server {
        preferred: 7201,
        valid: 7200,
        ..SERVER
    };
    let mut next = Output::default();
    client.receive(at, &reply(kind::ADVERTISE, &out.sends[0], &bad), &mut next);
    assert!(next.sends.is_empty());
    assert_eq!(client.state(), State::Soliciting);
}

//! The IPCP (RFC 1332, RFC 1877) and IPv6CP (RFC 5072) options.

use std::net::Ipv4Addr;

use ruster_pppoed::fsm::{Negotiation, Reply};
use ruster_pppoed::ipcp::IpcpOptions;
use ruster_pppoed::ipv6cp::Ipv6cpOptions;
use ruster_pppoed::ppp;
use ruster_pppoed::Rng;

fn options(bytes: &[u8]) -> Vec<(u8, &[u8])> {
    ppp::options(bytes).unwrap()
}

#[test]
fn ipcp_gets_the_address_and_dns_servers_from_naks() {
    let mut o = IpcpOptions::default();
    // Address 0.0.0.0 and both DNS servers 0.0.0.0.
    assert_eq!(
        o.request(),
        [3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0, 131, 6, 0, 0, 0, 0]
    );
    assert_eq!(o.address(), None);
    o.naked(&options(&[
        3, 6, 198, 51, 100, 2, 129, 6, 192, 0, 2, 53, 131, 6, 192, 0, 2, 54,
    ]));
    assert_eq!(
        o.request(),
        [3, 6, 198, 51, 100, 2, 129, 6, 192, 0, 2, 53, 131, 6, 192, 0, 2, 54]
    );
    assert_eq!(o.address(), Some(Ipv4Addr::new(198, 51, 100, 2)));
    assert_eq!(
        o.dns(),
        [Ipv4Addr::new(192, 0, 2, 53), Ipv4Addr::new(192, 0, 2, 54)]
    );
    // A peer without a secondary server rejects that option: not asked again.
    o.rejected(&options(&[131, 6, 192, 0, 2, 54]));
    assert_eq!(o.request(), [3, 6, 198, 51, 100, 2, 129, 6, 192, 0, 2, 53]);
    assert_eq!(o.dns(), [Ipv4Addr::new(192, 0, 2, 53)]);
    // An option we did not ask for in a Nak is ignored.
    o.naked(&options(&[2, 6, 0, 0x2d, 0x0f, 1]));
    assert_eq!(o.request().len(), 12);
}

#[test]
fn ipcp_peer_options() {
    let mut o = IpcpOptions::default();
    assert_eq!(
        o.check(&options(&[3, 6, 198, 51, 100, 1]), true),
        Reply::Ack
    );
    assert_eq!(o.peer, Some(Ipv4Addr::new(198, 51, 100, 1)));
    // No address at all is fine.
    assert_eq!(o.check(&[], true), Reply::Ack);
    assert_eq!(o.peer, None);
    // 0.0.0.0 (we have none to give), compression, or DNS asked of us: rejected.
    assert_eq!(
        o.check(&options(&[3, 6, 0, 0, 0, 0]), true),
        Reply::Reject(vec![3, 6, 0, 0, 0, 0])
    );
    assert_eq!(
        o.check(
            &options(&[3, 6, 198, 51, 100, 1, 2, 6, 0, 0x2d, 0x0f, 1, 129, 6, 0, 0, 0, 0]),
            true
        ),
        Reply::Reject(vec![2, 6, 0, 0x2d, 0x0f, 1, 129, 6, 0, 0, 0, 0])
    );
    // A wrong length.
    assert_eq!(
        o.check(&options(&[3, 5, 1, 2, 3]), true),
        Reply::Reject(vec![3, 5, 1, 2, 3])
    );
}

#[test]
fn ipv6cp_interface_identifiers() {
    let mut o = Ipv6cpOptions::new(Rng::new(5));
    let ours = o.local;
    assert_ne!(ours, [0; 8]);
    assert_eq!(ours[0] & 0x02, 0);
    assert_eq!(o.request(), [&[1, 10][..], &ours].concat());

    // Different and not 0: Ack.
    let peer = [0, 0, 0, 0, 0, 0, 0, 1];
    let request = [&[1, 10][..], &peer].concat();
    assert_eq!(o.check(&options(&request), true), Reply::Ack);
    assert_eq!(o.peer, Some(peer));

    // 0, or equal to ours: Nak with an identifier that is neither 0 nor ours.
    for id in [[0; 8], ours] {
        let request = [&[1, 10][..], &id].concat();
        let Reply::Nak(nak) = o.check(&options(&request), true) else {
            panic!("not a Nak");
        };
        assert_eq!(nak[..2], [1, 10]);
        assert_ne!(nak[2..], [0; 8]);
        assert_ne!(nak[2..], ours);
        assert_eq!(nak[2] & 0x02, 0);
    }

    // A Nak of ours gives the identifier to use, unless it is 0 or the peer's.
    let suggested = [2, 0, 0, 0, 0, 0, 0, 9];
    o.naked(&options(&[&[1, 10][..], &suggested].concat()));
    assert_eq!(o.local, suggested);
    o.naked(&options(&[&[1, 10][..], &peer].concat()));
    assert_ne!(o.local, peer);
    assert_ne!(o.local, [0; 8]);

    // Compression is rejected.
    assert_eq!(
        o.check(&options(&[2, 4, 0, 0x4f]), true),
        Reply::Reject(vec![2, 4, 0, 0x4f])
    );
}

#[test]
fn ipv6cp_both_zero_is_rejected() {
    let mut o = Ipv6cpOptions::new(Rng::new(5));
    o.rejected(&options(&[&[1, 10][..], &o.local.clone()].concat()));
    assert_eq!(o.local(), None);
    assert!(o.request().is_empty());
    // We ask for nothing (0), the peer asks for 0: Reject.
    let zero = [1, 10, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(o.check(&options(&zero), true), Reply::Reject(zero.to_vec()));
}

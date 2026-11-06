//! Punt message format tests.

use ruster_proto::punt::{reason, Direction, Punt, PuntError};

#[test]
fn punt_round_trips() {
    let frame = [1_u8, 2, 3];
    let punt = Punt {
        direction: Direction::ToControl,
        reason: reason::ARP,
        interface: "eth0",
        frame: &frame,
    };
    let mut out = Vec::new();
    punt.encode(&mut out).unwrap();
    assert_eq!(out, [1, 1, 0, 1, 4, b'e', b't', b'h', b'0', 1, 2, 3]);
    assert_eq!(Punt::decode(&out), Ok(punt));
}

#[test]
fn bad_punts_are_rejected() {
    assert_eq!(Punt::decode(&[1, 1, 0]), Err(PuntError::Truncated));
    assert_eq!(Punt::decode(&[2, 1, 0, 1, 0]), Err(PuntError::Version(2)));
    assert_eq!(Punt::decode(&[1, 3, 0, 1, 0]), Err(PuntError::Direction(3)));
    assert_eq!(
        Punt::decode(&[1, 1, 0, 1, 0]),
        Err(PuntError::InterfaceName)
    );
    assert_eq!(
        Punt::decode(&[1, 1, 0, 1, 5, b'a']),
        Err(PuntError::Truncated)
    );
    let long = "x".repeat(256);
    let punt = Punt {
        direction: Direction::FromControl,
        reason: reason::ARP,
        interface: &long,
        frame: &[],
    };
    assert_eq!(punt.encode(&mut Vec::new()), Err(PuntError::InterfaceName));
}

//! Claiming an address on a link: RFC 5227 Probe and Announcement.
//!
//! Without these a neighbour keeps a stale mapping until its own cache ages
//! out, which is exactly the wrong behaviour after an address moves to a new
//! link-layer address, and nothing checks whether an address is already in
//! use before this router starts answering for it.

use ruster_core::{
    execute_arp_announcement, ArpAnnouncementAction, ArpAnnouncementKind, IfId, Ipv4Address,
    MacAddress, NoGeneratedTrace, ARP_REQUEST_FRAME_LEN,
};
use ruster_io_sim::{FrameOrigin, SimIo};

const WAN: IfId = IfId(2);
const WAN_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);
const CLAIMED: Ipv4Address = Ipv4Address::from_octets([198, 51, 100, 1]);

fn emit(kind: ArpAnnouncementKind) -> Vec<u8> {
    let mut io = SimIo::new();
    let report = execute_arp_announcement(
        &mut io,
        ArpAnnouncementAction {
            kind,
            egress: WAN,
            source_mac: WAN_MAC,
            address: CLAIMED,
        },
        &mut NoGeneratedTrace,
    );
    assert!(report.completion.invariants_hold());
    assert_eq!(
        (report.completion.accepted, report.completion.rejected),
        (1, 0)
    );
    assert!(report.allocation_error.is_none());
    assert!(report.build_error.is_none());
    let tx = io.pop_tx().expect("the frame must reach the backend");
    assert_eq!(tx.origin, FrameOrigin::Generated);
    assert_eq!(tx.egress, WAN);
    assert!(io.pop_tx().is_none(), "exactly one frame");
    tx.bytes
}

fn assert_common_shape(bytes: &[u8]) {
    assert_eq!(bytes.len(), ARP_REQUEST_FRAME_LEN);
    assert_eq!(&bytes[0..6], &[0xff; 6], "broadcast to the link");
    assert_eq!(&bytes[6..12], &WAN_MAC.0);
    assert_eq!(&bytes[12..14], &0x0806_u16.to_be_bytes(), "ARP");
    assert_eq!(&bytes[14..16], &1_u16.to_be_bytes(), "Ethernet");
    assert_eq!(&bytes[16..18], &0x0800_u16.to_be_bytes(), "IPv4");
    assert_eq!(bytes[18], 6, "hardware length");
    assert_eq!(bytes[19], 4, "protocol length");
    assert_eq!(&bytes[20..22], &1_u16.to_be_bytes(), "Request");
    assert_eq!(&bytes[22..28], &WAN_MAC.0, "sender hardware address");
    // RFC 5227 §2.1.1 and §2.3: neither frame names a target station.
    assert_eq!(&bytes[32..38], &[0; 6], "target hardware address is zero");
    assert_eq!(&bytes[38..42], &CLAIMED.octets(), "target protocol address");
    assert_eq!(&bytes[42..], &[0; 18], "the frame is padded with zeroes");
}

#[test]
fn a_probe_claims_nothing_while_it_asks() {
    // RFC 5227 §2.1.1: the sender protocol address is all-zero, so a host that
    // already holds the address does not learn the prober's mapping and the
    // probe cannot be mistaken for a claim.
    let bytes = emit(ArpAnnouncementKind::Probe);
    assert_common_shape(&bytes);
    assert_eq!(
        &bytes[28..32],
        &[0; 4],
        "a probe must not put the address it is asking about in the sender field"
    );
}

#[test]
fn an_announcement_claims_the_address_in_both_protocol_fields() {
    // RFC 5227 §2.3: sender and target are both the claimed address, which is
    // what makes every listener refresh its cache.
    let bytes = emit(ArpAnnouncementKind::Announcement);
    assert_common_shape(&bytes);
    assert_eq!(&bytes[28..32], &CLAIMED.octets(), "sender protocol address");
}

#[test]
fn a_probe_and_an_announcement_differ_only_in_the_sender_protocol_address() {
    let probe = emit(ArpAnnouncementKind::Probe);
    let announcement = emit(ArpAnnouncementKind::Announcement);
    let differing: Vec<usize> = (0..probe.len())
        .filter(|index| probe[*index] != announcement[*index])
        .collect();
    assert_eq!(
        differing,
        (28..32).collect::<Vec<_>>(),
        "only the sender protocol address distinguishes them"
    );
}

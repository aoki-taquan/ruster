use ruster_core::{
    forward_batch, forward_batch_with_icmpv4_timestamp, internet_checksum, ipv4_header_checksum,
    ConsumeReason, DropReason, ForwardingSnapshot, Icmpv4TimestampClock, IfId, Interface,
    Ipv4Address, Ipv4Mtu, LocalIpv4Binding, MacAddress, NoTrace, PacketIo,
};
use ruster_io_sim::{RecycleCause, SimIo};

const LAN: IfId = IfId(1);
const LOCAL_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x20];
const LOCAL_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 1]);
const PEER_IP: Ipv4Address = Ipv4Address::from_octets([192, 0, 2, 20]);

fn interfaces() -> [Interface; 1] {
    [Interface {
        id: LAN,
        mac: LOCAL_MAC,
        mtu: Ipv4Mtu::ETHERNET,
    }]
}

fn bindings() -> [LocalIpv4Binding; 1] {
    [LocalIpv4Binding {
        interface: LAN,
        address: LOCAL_IP,
    }]
}

fn snapshot<'a>(
    interfaces: &'a [Interface; 1],
    bindings: &'a [LocalIpv4Binding; 1],
) -> ForwardingSnapshot<'a> {
    ForwardingSnapshot::new(&[], interfaces, &[], bindings).unwrap()
}

/// A Timestamp message body: identifier, sequence, originate, receive, and
/// transmit timestamps.
fn timestamp_message(kind: u8, code: u8, originate: u32) -> Vec<u8> {
    let mut message = vec![0_u8; 20];
    message[0] = kind;
    message[1] = code;
    message[4..6].copy_from_slice(&0x4567_u16.to_be_bytes());
    message[6..8].copy_from_slice(&0x89ab_u16.to_be_bytes());
    message[8..12].copy_from_slice(&originate.to_be_bytes());
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn ipv4_frame(protocol: u8, ttl: u8, body: &[u8]) -> Vec<u8> {
    let total_len = 20 + body.len();
    let mut frame = vec![0_u8; 14 + total_len];
    frame[0..6].copy_from_slice(&LOCAL_MAC.0);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&u16::try_from(total_len).unwrap().to_be_bytes());
    frame[20..22].copy_from_slice(&0_u16.to_be_bytes());
    frame[22] = ttl;
    frame[23] = protocol;
    frame[26..30].copy_from_slice(&PEER_IP.octets());
    frame[30..34].copy_from_slice(&LOCAL_IP.octets());
    frame[34..34 + body.len()].copy_from_slice(body);
    let checksum = ipv4_header_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn timestamp_request(originate: u32) -> Vec<u8> {
    ipv4_frame(1, 64, &timestamp_message(13, 0, originate))
}

/// RFC 792 / RFC 1812 §4.3.2.9: a Timestamp request addressed to this
/// router's own address draws a Timestamp Reply carrying the receive and
/// transmit timestamps the caller's clock reports.
#[test]
fn timestamp_reply_is_in_place_exact_and_carries_the_supplied_clock() {
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = snapshot(&interfaces, &bindings);
    let request = timestamp_request(0x1234_5678);
    let mut io = SimIo::new();
    io.inject(LAN, request.clone());

    let report = forward_batch_with_icmpv4_timestamp(
        io.receive(1).unwrap(),
        &snapshot,
        Icmpv4TimestampClock(12_345_678),
        &mut NoTrace,
    );

    assert_eq!(
        (report.tx_requested, report.dropped, report.consumed),
        (1, 0, 0)
    );
    let tx = io.pop_tx().unwrap();
    assert_eq!(&tx.bytes[0..6], &PEER_MAC);
    assert_eq!(&tx.bytes[6..12], &LOCAL_MAC.0);
    assert_eq!(&tx.bytes[26..30], &LOCAL_IP.octets());
    assert_eq!(&tx.bytes[30..34], &PEER_IP.octets());
    assert_eq!(ipv4_header_checksum(&tx.bytes[14..34]), 0);
    assert_eq!(tx.bytes[34], 14, "Timestamp Reply");
    assert_eq!(tx.bytes[35], 0);
    // Identifier and sequence number are echoed unchanged.
    assert_eq!(&tx.bytes[38..42], &request[38..42]);
    // Originate timestamp is echoed unchanged from the request.
    assert_eq!(&tx.bytes[42..46], &0x1234_5678_u32.to_be_bytes());
    // Receive and transmit timestamps both carry the supplied clock value.
    assert_eq!(&tx.bytes[46..50], &12_345_678_u32.to_be_bytes());
    assert_eq!(&tx.bytes[50..54], &12_345_678_u32.to_be_bytes());
    assert_eq!(internet_checksum(&tx.bytes[34..54]), 0);
}

/// With no clock supplied, a Timestamp request is simply consumed: the
/// datapath never reads a clock of its own, so it cannot fabricate a reply.
#[test]
fn timestamp_request_without_a_clock_is_consumed_unanswered() {
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = snapshot(&interfaces, &bindings);
    let request = timestamp_request(1);
    let original = request.clone();
    let mut io = SimIo::new();
    io.inject(LAN, request);

    let report = io.run_once(1, &snapshot, &mut NoTrace).unwrap();

    assert_eq!(
        (report.tx_requested, report.dropped, report.consumed),
        (0, 0, 1)
    );
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Consumed(ConsumeReason::Ipv4LocalUnsupported)
    );
    assert_eq!(recycled.bytes, original);
}

/// A non-zero code is invalid regardless of clock availability.
#[test]
fn timestamp_request_with_a_nonzero_code_is_an_atomic_drop() {
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = snapshot(&interfaces, &bindings);
    let request = timestamp_request(1)
        .into_iter()
        .enumerate()
        .map(|(index, byte)| if index == 35 { 1 } else { byte })
        .collect::<Vec<u8>>();
    let mut fixed = request.clone();
    // Recompute the ICMP checksum so only the code field is wrong.
    let icmp_offset = 34;
    fixed[icmp_offset + 2..icmp_offset + 4].fill(0);
    let checksum = internet_checksum(&fixed[icmp_offset..]);
    fixed[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    let original = fixed.clone();
    let mut io = SimIo::new();
    io.inject(LAN, fixed);

    let report = forward_batch_with_icmpv4_timestamp(
        io.receive(1).unwrap(),
        &snapshot,
        Icmpv4TimestampClock(1),
        &mut NoTrace,
    );

    assert_eq!((report.tx_requested, report.dropped), (0, 1));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Icmpv4TimestampCodeInvalid)
    );
    assert_eq!(recycled.bytes, original);
}

/// A Timestamp message shorter than the fixed 20-byte body is truncated.
#[test]
fn timestamp_request_shorter_than_twenty_bytes_is_an_atomic_drop() {
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = snapshot(&interfaces, &bindings);
    let mut short = timestamp_message(13, 0, 0);
    short.truncate(19);
    short[2..4].fill(0);
    let checksum = internet_checksum(&short);
    short[2..4].copy_from_slice(&checksum.to_be_bytes());
    let frame = ipv4_frame(1, 64, &short);
    let original = frame.clone();
    let mut io = SimIo::new();
    io.inject(LAN, frame);

    let report = forward_batch_with_icmpv4_timestamp(
        io.receive(1).unwrap(),
        &snapshot,
        Icmpv4TimestampClock(1),
        &mut NoTrace,
    );

    assert_eq!((report.tx_requested, report.dropped), (0, 1));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Icmpv4TimestampHeaderTruncated)
    );
    assert_eq!(recycled.bytes, original);
}

/// An invalid ICMP checksum is rejected before the clock is even consulted.
#[test]
fn timestamp_request_with_an_invalid_checksum_is_an_atomic_drop() {
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = snapshot(&interfaces, &bindings);
    let mut request = timestamp_request(1);
    request[36] ^= 0xff;
    let original = request.clone();
    let mut io = SimIo::new();
    io.inject(LAN, request);

    let report = forward_batch_with_icmpv4_timestamp(
        io.receive(1).unwrap(),
        &snapshot,
        Icmpv4TimestampClock(1),
        &mut NoTrace,
    );

    assert_eq!((report.tx_requested, report.dropped), (0, 1));
    let recycled = io.pop_recycled().unwrap();
    assert_eq!(
        recycled.cause,
        RecycleCause::Forwarding(DropReason::Icmpv4ChecksumInvalid)
    );
    assert_eq!(recycled.bytes, original);
}

/// A plain `forward_batch` caller with no timestamp support at all still
/// consumes a Timestamp request without answering it, exactly like the
/// no-clock case.
#[test]
fn bare_forward_batch_never_answers_a_timestamp_request() {
    let interfaces = interfaces();
    let bindings = bindings();
    let snapshot = snapshot(&interfaces, &bindings);
    let request = timestamp_request(1);
    let mut io = SimIo::new();
    io.inject(LAN, request);

    let report = forward_batch(io.receive(1).unwrap(), &snapshot, &mut NoTrace);

    assert_eq!(
        (report.tx_requested, report.dropped, report.consumed),
        (0, 0, 1)
    );
}

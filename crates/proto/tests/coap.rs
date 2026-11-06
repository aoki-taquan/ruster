//! CoAP framing tests (RFC 8323 section 3.2, options from RFC 7252 section 3.1).

use ruster_proto::coap::{
    decode, encode, option, read_uint_option, uint_option, Code, Decoded, EncodeError, FrameError,
    Message,
};

const LIMIT: usize = 16 * 1024 * 1024;

fn encoded(code: Code, token: &[u8], options: &[(u16, &[u8])], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode(&mut out, code, token, options, payload).unwrap();
    out
}

fn whole(buf: &[u8]) -> (Message<'_>, usize) {
    match decode(buf, LIMIT).unwrap() {
        Decoded::Message(message, used) => (message, used),
        Decoded::NeedMore(n) => panic!("needs {n} more bytes"),
    }
}

#[test]
fn ping_is_two_bytes() {
    // Len 0, TKL 0, code 7.02.
    assert_eq!(encoded(Code::PING, &[], &[], &[]), [0x00, 0xe2]);
}

#[test]
fn get_with_one_path_segment() {
    // Len 2 (option header + "c"), code 0.01, option 11 with delta 11 and length 1.
    let bytes = encoded(Code::GET, &[], &[(option::URI_PATH, b"c")], &[]);
    assert_eq!(bytes, [0x20, 0x01, 0xb1, b'c']);
    let (message, used) = whole(&bytes);
    assert_eq!(used, 4);
    assert_eq!(message.code, Code::GET);
    assert_eq!(message.option(option::URI_PATH), Some(&b"c"[..]));
    assert!(message.payload.is_empty());
}

#[test]
fn full_message_round_trips() {
    let mut cf = [0; 4];
    let options = [
        (option::URI_PATH, &b"c"[..]),
        (option::URI_PATH, &b"fib"[..]),
        (option::CONTENT_FORMAT, uint_option(142, &mut cf)),
    ];
    let payload = [0xa1, 0x19, 0xea, 0x6a, 0xf6];
    let bytes = encoded(Code::IPATCH, &[1, 2, 3], &options, &payload);
    let (message, used) = whole(&bytes);
    assert_eq!(used, bytes.len());
    assert_eq!(message.code, Code::IPATCH);
    assert_eq!(message.token, [1, 2, 3]);
    assert_eq!(message.payload, payload);
    let got: Vec<_> = message.options().collect();
    assert_eq!(got, options);
    assert_eq!(
        message
            .option(option::CONTENT_FORMAT)
            .and_then(read_uint_option),
        Some(142)
    );
}

#[test]
fn every_length_form_round_trips() {
    // Body lengths at the edges of the 0, 1, 2 and 4 byte extended length forms.
    for payload_len in [11, 12, 267, 268, 65_803, 65_804, 70_000] {
        let payload = vec![0x5a; payload_len];
        let bytes = encoded(Code::CONTENT, &[9], &[], &payload);
        let (message, used) = whole(&bytes);
        assert_eq!(used, bytes.len(), "{payload_len}");
        assert_eq!(message.payload.len(), payload_len);
    }
}

#[test]
fn every_option_form_round_trips() {
    let long = vec![7; 300];
    let longest = vec![8; 65_804];
    let options = [
        (1, &b""[..]),
        (14, &b"x"[..]),
        (300, &long[..]),
        (65_535, &longest[..]),
    ];
    let bytes = encoded(Code::POST, &[], &options, b"p");
    let (message, _) = whole(&bytes);
    let got: Vec<_> = message.options().collect();
    assert_eq!(got, options);
}

#[test]
fn partial_input_asks_for_more() {
    let bytes = encoded(Code::CONTENT, &[1], &[], &[0; 300]);
    for cut in 0..bytes.len() {
        match decode(&bytes[..cut], LIMIT).unwrap() {
            Decoded::NeedMore(n) => assert!(n >= 1 && cut + n <= bytes.len(), "{cut}"),
            Decoded::Message(..) => panic!("decoded from {cut} bytes"),
        }
    }
}

#[test]
fn messages_follow_each_other_in_a_stream() {
    let mut stream = encoded(Code::PING, &[], &[], &[]);
    stream.extend(encoded(Code::CONTENT, &[4], &[], b"hello"));
    let (first, used) = whole(&stream);
    assert_eq!(first.code, Code::PING);
    let (second, _) = whole(&stream[used..]);
    assert_eq!(second.payload, b"hello");
}

#[test]
fn oversized_messages_are_refused_from_the_header() {
    // Len 15 with a 4-byte extension claiming about 4 GiB; nothing else is present.
    let header = [0xf0, 0xff, 0xff, 0xff, 0xff];
    assert!(matches!(
        decode(&header, LIMIT),
        Err(FrameError::TooLarge { .. })
    ));
    let bytes = encoded(Code::CONTENT, &[], &[], &[0; 100]);
    assert!(matches!(
        decode(&bytes, 50),
        Err(FrameError::TooLarge { .. })
    ));
}

#[test]
fn malformed_messages_are_rejected() {
    let cases: &[(&[u8], FrameError)] = &[
        // TKL 9.
        (&[0x09, 0x01], FrameError::BadTokenLength),
        // Option header with the reserved delta 15 (not a payload marker).
        (&[0x10, 0x01, 0xf0], FrameError::BadOption),
        // Option length 15 is reserved too.
        (&[0x10, 0x01, 0x0f], FrameError::BadOption),
        // Option claims 2 value bytes, only 1 present.
        (&[0x20, 0x01, 0x02, 0x00], FrameError::TruncatedOption),
        // Payload marker with nothing after it.
        (&[0x10, 0x01, 0xff], FrameError::EmptyPayload),
        // Two options whose numbers add up past 65535: 65535 then +1.
        (
            &[0x40, 0x01, 0xe0, 0xfe, 0xf2, 0x10],
            FrameError::OptionNumberOverflow,
        ),
    ];
    for &(bytes, error) in cases {
        assert_eq!(decode(bytes, LIMIT), Err(error), "{bytes:02x?}");
    }
}

#[test]
fn encoder_rejects_bad_input() {
    let mut out = Vec::new();
    assert_eq!(
        encode(&mut out, Code::GET, &[0; 9], &[], &[]),
        Err(EncodeError::TokenTooLong)
    );
    assert_eq!(
        encode(&mut out, Code::GET, &[], &[(12, b""), (11, b"")], &[]),
        Err(EncodeError::OptionsOutOfOrder)
    );
    let too_long = vec![0; 65_805];
    assert_eq!(
        encode(&mut out, Code::GET, &[], &[(11, &too_long[..])], &[]),
        Err(EncodeError::OptionTooLong)
    );
    assert!(out.is_empty());
}

#[test]
fn codes_print_as_class_and_detail() {
    assert_eq!(Code::IPATCH.to_string(), "0.07");
    assert_eq!(Code::CHANGED.to_string(), "2.04");
    assert_eq!(Code::CSM.to_string(), "7.01");
    assert_eq!(Code::NOT_FOUND.class(), 4);
    assert_eq!(Code::NOT_FOUND.detail(), 4);
}

#[test]
fn uint_options_have_no_leading_zeros() {
    let mut buf = [0; 4];
    assert_eq!(uint_option(0, &mut buf), &[] as &[u8]);
    assert_eq!(uint_option(60, &mut buf), &[60]);
    assert_eq!(uint_option(256, &mut buf), &[1, 0]);
    assert_eq!(uint_option(16 * 1024 * 1024, &mut buf), &[1, 0, 0, 0]);
    assert_eq!(read_uint_option(&[]), Some(0));
    assert_eq!(read_uint_option(&[1, 0]), Some(256));
    assert_eq!(read_uint_option(&[1, 0, 0, 0, 0]), None);
}

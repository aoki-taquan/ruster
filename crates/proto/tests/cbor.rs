//! CBOR subset tests. Byte strings come from RFC 8949 Appendix A where it has them.

use ruster_proto::cbor::{DecodeError, Decoder, Encoder, Kind, Unsupported};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn encode(f: impl FnOnce(&mut Encoder<'_>)) -> Vec<u8> {
    let mut out = Vec::new();
    f(&mut Encoder::new(&mut out));
    out
}

#[test]
fn unsigned_integers_match_rfc_8949_appendix_a() {
    let cases: &[(u64, &str)] = &[
        (0, "00"),
        (1, "01"),
        (10, "0a"),
        (23, "17"),
        (24, "1818"),
        (25, "1819"),
        (100, "1864"),
        (1000, "1903e8"),
        (1_000_000, "1a000f4240"),
        (1_000_000_000_000, "1b000000e8d4a51000"),
        (u64::MAX, "1bffffffffffffffff"),
    ];
    for &(value, bytes) in cases {
        assert_eq!(
            encode(|e| {
                e.u64(value);
            }),
            hex(bytes),
            "{value}"
        );
        let input = hex(bytes);
        let mut d = Decoder::new(&input);
        assert_eq!(d.u64(), Ok(value));
        assert!(d.is_empty());
    }
}

#[test]
fn signed_integers_match_rfc_8949_appendix_a() {
    let cases: &[(i64, &str)] = &[
        (-1, "20"),
        (-10, "29"),
        (-100, "3863"),
        (-1000, "3903e7"),
        (i64::MIN, "3b7fffffffffffffff"),
        (i64::MAX, "1b7fffffffffffffff"),
    ];
    for &(value, bytes) in cases {
        assert_eq!(
            encode(|e| {
                e.i64(value);
            }),
            hex(bytes),
            "{value}"
        );
        let input = hex(bytes);
        assert_eq!(Decoder::new(&input).i64(), Ok(value));
    }
}

#[test]
fn integers_outside_i64_are_out_of_range() {
    // -18446744073709551616 from RFC 8949 Appendix A, and u64::MAX.
    for bytes in ["3bffffffffffffffff", "1bffffffffffffffff"] {
        let input = hex(bytes);
        assert_eq!(
            Decoder::new(&input).i64(),
            Err(DecodeError::OutOfRange { at: 0 })
        );
    }
}

#[test]
fn strings_match_rfc_8949_appendix_a() {
    assert_eq!(
        encode(|e| {
            e.bytes(&[]);
        }),
        hex("40")
    );
    assert_eq!(
        encode(|e| {
            e.bytes(&[1, 2, 3, 4]);
        }),
        hex("4401020304")
    );
    let texts: &[(&str, &str)] = &[
        ("", "60"),
        ("a", "6161"),
        ("IETF", "6449455446"),
        ("\"\\", "62225c"),
        ("\u{fc}", "62c3bc"),
        ("\u{6c34}", "63e6b0b4"),
    ];
    for &(value, bytes) in texts {
        assert_eq!(
            encode(|e| {
                e.text(value);
            }),
            hex(bytes)
        );
        let input = hex(bytes);
        assert_eq!(Decoder::new(&input).text(), Ok(value));
    }
}

#[test]
fn nested_containers_round_trip() {
    // {"a": 1, "b": [2, 3]} from RFC 8949 Appendix A.
    let bytes = encode(|e| {
        e.map(2).text("a").u64(1).text("b").array(2).u64(2).u64(3);
    });
    assert_eq!(bytes, hex("a26161016162820203"));

    let mut d = Decoder::new(&bytes);
    assert_eq!(d.map(), Ok(2));
    assert_eq!(d.text(), Ok("a"));
    assert_eq!(d.u64(), Ok(1));
    assert_eq!(d.text(), Ok("b"));
    assert_eq!(d.array(), Ok(2));
    assert_eq!(d.u64(), Ok(2));
    assert_eq!(d.u64(), Ok(3));
    assert!(d.is_empty());
}

#[test]
fn simple_values_match_rfc_8949_appendix_a() {
    assert_eq!(
        encode(|e| {
            e.bool(false).bool(true).null();
        }),
        hex("f4f5f6")
    );
    let input = hex("f4f5f6");
    let mut d = Decoder::new(&input);
    assert_eq!(d.peek_kind(), Ok(Kind::Bool));
    assert_eq!(d.bool(), Ok(false));
    assert_eq!(d.bool(), Ok(true));
    assert_eq!(d.peek_kind(), Ok(Kind::Null));
    assert_eq!(d.null(), Ok(()));
    assert!(d.is_empty());
}

#[test]
fn sequence_items_are_read_in_order() {
    // An iPATCH-like body: two maps one after another (RFC 8742 sequence).
    let bytes = encode(|e| {
        e.map(1).array(2).u64(60010).text("192.0.2.0/24").null();
        e.map(1).u64(60011).bool(true);
    });
    let mut d = Decoder::new(&bytes);
    let mut items = 0;
    while !d.is_empty() {
        d.skip().unwrap();
        items += 1;
    }
    assert_eq!(items, 2);
}

#[test]
fn wrong_kind_consumes_nothing() {
    let input = hex("6161");
    let mut d = Decoder::new(&input);
    assert_eq!(
        d.u64(),
        Err(DecodeError::WrongKind {
            at: 0,
            expected: Kind::Unsigned,
            found: Kind::Text
        })
    );
    assert_eq!(d.position(), 0);
    assert_eq!(d.text(), Ok("a"));
}

#[test]
fn longer_heads_than_needed_are_accepted() {
    // 1 written with a two-byte argument.
    let input = hex("190001");
    assert_eq!(Decoder::new(&input).u64(), Ok(1));
}

#[test]
fn unsupported_parts_are_rejected() {
    let cases: &[(&str, Unsupported)] = &[
        ("5f4101ff", Unsupported::IndefiniteLength),
        ("9fff", Unsupported::IndefiniteLength),
        ("ff", Unsupported::IndefiniteLength),
        ("c11a514b67b0", Unsupported::Tag),
        ("f93c00", Unsupported::Float),
        ("fa47c35000", Unsupported::Float),
        ("fb3ff199999999999a", Unsupported::Float),
        ("f7", Unsupported::SimpleValue),
        ("f818", Unsupported::SimpleValue),
        ("f814", Unsupported::SimpleValue),
        ("1c", Unsupported::ReservedHead),
    ];
    for &(bytes, what) in cases {
        let input = hex(bytes);
        assert_eq!(
            Decoder::new(&input).skip(),
            Err(DecodeError::Unsupported { at: 0, what }),
            "{bytes}"
        );
    }
}

#[test]
fn truncated_input_is_rejected() {
    for bytes in ["", "18", "1903", "4401", "62c3", "8201", "a101"] {
        let input = hex(bytes);
        assert_eq!(
            Decoder::new(&input).skip(),
            Err(DecodeError::UnexpectedEnd),
            "{bytes}"
        );
    }
}

#[test]
fn huge_declared_lengths_fail_without_allocating() {
    // A byte string and an array that claim u64::MAX entries.
    for bytes in ["5bffffffffffffffff", "9bffffffffffffffff00"] {
        let input = hex(bytes);
        assert_eq!(Decoder::new(&input).skip(), Err(DecodeError::UnexpectedEnd));
    }
}

#[test]
fn deep_nesting_is_skipped_without_recursion() {
    let mut input = vec![0x81; 100_000];
    input.push(0x00);
    let mut d = Decoder::new(&input);
    assert_eq!(d.skip(), Ok(()));
    assert!(d.is_empty());
}

#[test]
fn invalid_utf8_is_rejected() {
    let input = hex("62c328");
    assert_eq!(
        Decoder::new(&input).text(),
        Err(DecodeError::InvalidUtf8 { at: 0 })
    );
}

#[test]
fn container_counts_larger_than_the_input_are_rejected() {
    for bytes in ["9bffffffffffffffff", "bbffffffffffffffff", "8301", "a20101"] {
        let input = hex(bytes);
        let mut d = Decoder::new(&input);
        let result = if bytes.starts_with('9') || bytes.starts_with('8') {
            d.array()
        } else {
            d.map()
        };
        assert_eq!(result, Err(DecodeError::UnexpectedEnd), "{bytes}");
        assert_eq!(
            Decoder::new(&input).skip(),
            Err(DecodeError::UnexpectedEnd),
            "{bytes}"
        );
    }
}

#[test]
fn truncated_tags_and_floats_are_named() {
    for (bytes, what) in [("d8", Unsupported::Tag), ("f93c", Unsupported::Float)] {
        let input = hex(bytes);
        assert_eq!(
            Decoder::new(&input).skip(),
            Err(DecodeError::Unsupported { at: 0, what }),
            "{bytes}"
        );
    }
}

#[test]
fn every_reader_consumes_nothing_on_wrong_kind() {
    let input = hex("00");
    let mut d = Decoder::new(&input);
    assert!(d.bytes().is_err());
    assert!(d.text().is_err());
    assert!(d.array().is_err());
    assert!(d.map().is_err());
    assert!(d.bool().is_err());
    assert!(d.null().is_err());
    assert_eq!(d.position(), 0);
    let input = hex("6161");
    let mut d = Decoder::new(&input);
    assert!(d.i64().is_err());
    assert_eq!(d.position(), 0);
}

#[test]
fn heads_round_trip_at_every_size_boundary() {
    for value in [
        23u64,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        1 << 32,
    ] {
        let bytes = encode(|e| {
            e.u64(value).array(value).map(value);
        });
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.u64(), Ok(value));
        // The container heads are read raw; their counts exceed the input on purpose.
        assert_eq!(d.peek_kind(), Ok(Kind::Array));
    }
}

#[test]
fn truncated_head_inside_a_container_is_rejected() {
    let input = hex("8218");
    assert_eq!(Decoder::new(&input).skip(), Err(DecodeError::UnexpectedEnd));
}

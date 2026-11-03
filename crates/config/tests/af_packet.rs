//! `[backend.af-packet]` schema and validation (CONFIG-009): the
//! AF_PACKET (TPACKET_V3) backend of `ruster run` (AFPKT-015).

use ruster_config::{
    parse, validate, BackendKindV1, DiagnosticCode, PathSegment, ValidatedConfig,
    ValidatedConfigV1, ValidationCode, ValidationError, ValidationLimits,
    DEFAULT_AF_PACKET_FRAME_LEN, MAX_AF_PACKET_BLOCK_COUNT, MAX_AF_PACKET_BLOCK_SIZE,
    MAX_AF_PACKET_FRAME_LEN, MAX_AF_PACKET_RETIRE_TIMEOUT_MS, MAX_AF_PACKET_RING_BYTES,
    MAX_AF_PACKET_RING_BYTES_PER_PORT, MAX_BACKEND_PORTS, MIN_AF_PACKET_BLOCK_SIZE,
    MIN_AF_PACKET_FRAME_LEN,
};
use ruster_core::IfId;
use ruster_io_afpacket::{PortConfig, RingGeometry, ValidatedConfig as PacketConfig};

const LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 16,
    max_quote_slots_per_table: 1 << 16,
    max_runtime_bytes: 1 << 26,
};

/// Interfaces `if0`..`if{count-1}` (IfId 1..) on devices `eth0`.. and
/// nothing else: backend validation needs no service.
fn interfaces(count: usize) -> String {
    let mut text = String::from("schema-version = 1\n");
    for index in 0..count {
        text.push_str(&format!(
            "\n[[interfaces]]\nid = {}\nname = \"if{index}\"\ndevice = \"eth{index}\"\n\
             mac = \"02:00:00:00:00:{:02x}\"\n",
            index + 1,
            index + 1
        ));
    }
    text
}

/// One `[[backend.af-packet.ports]]` entry with the documented example
/// geometry.
fn port(interface: &str) -> String {
    format!(
        "\n[[backend.af-packet.ports]]\ninterface = \"{interface}\"\n\
         rx = {{ block-size = 65536, block-count = 8, retire-timeout-ms = 4 }}\n\
         tx = {{ block-size = 65536, block-count = 4 }}\n"
    )
}

/// Two interfaces, both bound; the ports are listed `if1` first.
fn two_ports(head: &str) -> String {
    format!(
        "{}\n[backend]\nkind = \"af-packet\"\n\n[backend.af-packet]\n{head}{}{}",
        interfaces(2),
        port("if1"),
        port("if0")
    )
}

/// `two_ports("")` with exactly one replacement of `from` (which must occur
/// once) in the first port entry.
fn edited(from: &str, to: &str) -> String {
    let text = two_ports("");
    let first = text.find("[[backend.af-packet.ports]]").unwrap();
    let second = text[first + 1..]
        .find("[[backend.af-packet.ports]]")
        .unwrap()
        + first
        + 1;
    let (head, rest) = text.split_at(second);
    let (prefix, port) = head.split_at(first);
    assert_eq!(port.matches(from).count(), 1, "anchor {from:?}");
    format!("{prefix}{}{rest}", port.replacen(from, to, 1))
}

fn check(text: &str) -> Result<ValidatedConfigV1, ValidationError> {
    match validate(parse(text.as_bytes()).expect("syntax"), LIMITS)? {
        ValidatedConfig::V1(config) => Ok(config),
        _ => unreachable!("schema V1"),
    }
}

fn reject(text: &str) -> ValidationError {
    match check(text) {
        Ok(_) => panic!("accepted"),
        Err(error) => error,
    }
}

fn rendered(path: &[PathSegment]) -> String {
    let mut text = String::new();
    for segment in path {
        match segment {
            PathSegment::Field(field) => {
                if !text.is_empty() {
                    text.push('.');
                }
                text.push_str(field);
            }
            PathSegment::Index(index) => text.push_str(&format!("[{index}]")),
            _ => text.push_str("[?]"),
        }
    }
    text
}

#[test]
fn af_packet_backend_validates_to_derived_ring_geometry() {
    let config = check(&two_ports("")).unwrap();
    let backend = config.backend();
    assert_eq!(backend.kind(), BackendKindV1::AfPacket);
    assert_eq!(BackendKindV1::AfPacket.config_name(), "af-packet");
    assert!(backend.af_xdp().is_none());
    let packet = backend.af_packet().expect("af-packet");
    assert_eq!(packet.max_frame_len(), DEFAULT_AF_PACKET_FRAME_LEN);
    assert_eq!(packet.max_frame_len(), 1_514);
    // Sorted by IfId although `if1` came first.
    let interfaces: Vec<IfId> = packet.ports().iter().map(|port| port.interface()).collect();
    assert_eq!(interfaces, [IfId(1), IfId(2)]);
    let first = &packet.ports()[0];
    assert_eq!(first.device(), "eth0");
    let (rx, tx) = (first.rx(), first.tx());
    // 82 + 1514 = 1596 -> 1600 aligned -> 2048; 48 + 1514 = 1562 -> 2048.
    assert_eq!(
        (rx.block_size(), rx.block_count(), rx.frame_size()),
        (65_536, 8, 2_048)
    );
    assert_eq!(rx.frame_count(), 32 * 8);
    assert_eq!(rx.retire_timeout_ms(), 4);
    assert_eq!(
        (tx.block_size(), tx.block_count(), tx.frame_size()),
        (65_536, 4, 2_048)
    );
    assert_eq!(tx.frame_count(), 32 * 4);
    assert_eq!(tx.retire_timeout_ms(), 0);
    assert_eq!(packet.ring_bytes(), 2 * (8 + 4) * 65_536);

    // A jumbo maximum frame derives larger slots.
    let jumbo = check(&two_ports("max-frame-len = 9014\n")).unwrap();
    let port = &jumbo.backend().af_packet().unwrap().ports()[0];
    assert_eq!(port.rx().frame_size(), 16_384);
    assert_eq!(port.tx().frame_size(), 16_384);
    assert_eq!(port.rx().frame_count(), 4 * 8);
}

type Case = (String, ValidationCode, &'static str, Option<(u64, u64)>);

#[test]
fn af_packet_backend_rejects_every_rule_with_a_value_free_path() {
    let cases: Vec<Case> = vec![
        (
            format!(
                "{}\n[backend]\nkind = \"af-xdp\"\n\n[backend.af-packet]\n{}",
                interfaces(1),
                port("if0")
            ),
            ValidationCode::BackendAfPacketWithoutKind,
            "backend.af-packet",
            None,
        ),
        (
            format!(
                "{}\n[backend]\n\n[backend.af-packet]\n{}",
                interfaces(1),
                port("if0")
            ),
            ValidationCode::BackendAfPacketWithoutKind,
            "backend.af-packet",
            None,
        ),
        (
            format!(
                "{}\n[backend]\nkind = \"af-packet\"\n\n[[backend.ports]]\ninterface = \"if0\"\n\
                 queue = 0\nmode = \"copy\"\nxdp-attach = \"native\"\n\
                 rings = {{ fill = 64, rx = 64, tx = 64, completion = 64 }}\n\
                 frame-size = 2048\nframe-count = 256\ngenerated-frames = 64\n",
                interfaces(1)
            ),
            ValidationCode::BackendPortsWithoutAfXdp,
            "backend.ports",
            None,
        ),
        (
            format!("{}\n[backend]\nkind = \"af-packet\"\n", interfaces(1)),
            ValidationCode::BackendNoPorts,
            "backend.af-packet.ports",
            None,
        ),
        (
            format!(
                "{}\n[backend]\nkind = \"af-packet\"\n\n[backend.af-packet]\nmax-frame-len = 1514\n",
                interfaces(1)
            ),
            ValidationCode::BackendNoPorts,
            "backend.af-packet.ports",
            None,
        ),
        (
            edited("interface = \"if1\"", "interface = \"nosuchif\""),
            ValidationCode::UnknownInterface,
            "backend.af-packet.ports[0].interface",
            None,
        ),
        (
            edited("interface = \"if1\"", "interface = \"if0\""),
            ValidationCode::BackendDuplicateInterface,
            "backend.af-packet.ports[1].interface",
            None,
        ),
        (
            format!(
                "{}\n[backend]\nkind = \"af-packet\"\n\n[backend.af-packet]\n{}",
                interfaces(2),
                port("if1")
            ),
            ValidationCode::BackendInterfaceUnbound,
            "interfaces[0].name",
            None,
        ),
        (
            two_ports("max-frame-len = 589\n"),
            ValidationCode::BackendMaxFrameLenOutOfRange,
            "backend.af-packet.max-frame-len",
            Some((u64::from(MIN_AF_PACKET_FRAME_LEN), 589)),
        ),
        (
            two_ports("max-frame-len = 9231\n"),
            ValidationCode::BackendMaxFrameLenOutOfRange,
            "backend.af-packet.max-frame-len",
            Some((u64::from(MAX_AF_PACKET_FRAME_LEN), 9_231)),
        ),
        (
            edited("rx = { block-size = 65536", "rx = { block-size = 65535"),
            ValidationCode::BackendBlockSizeInvalid,
            "backend.af-packet.ports[0].rx.block-size",
            None,
        ),
        (
            edited("rx = { block-size = 65536", "rx = { block-size = 2048"),
            ValidationCode::BackendBlockSizeInvalid,
            "backend.af-packet.ports[0].rx.block-size",
            None,
        ),
        (
            edited("tx = { block-size = 65536", "tx = { block-size = 8388608"),
            ValidationCode::BackendBlockSizeInvalid,
            "backend.af-packet.ports[0].tx.block-size",
            None,
        ),
        (
            edited("rx = { block-size = 65536", "rx = { block-size = 0"),
            ValidationCode::BackendBlockSizeInvalid,
            "backend.af-packet.ports[0].rx.block-size",
            None,
        ),
        (
            edited("block-count = 8", "block-count = 0"),
            ValidationCode::BackendBlockCountOutOfRange,
            "backend.af-packet.ports[0].rx.block-count",
            Some((1, 0)),
        ),
        (
            edited("block-count = 4", "block-count = 65537"),
            ValidationCode::BackendBlockCountOutOfRange,
            "backend.af-packet.ports[0].tx.block-count",
            Some((u64::from(MAX_AF_PACKET_BLOCK_COUNT), 65_537)),
        ),
        (
            edited("retire-timeout-ms = 4", "retire-timeout-ms = 0"),
            ValidationCode::BackendRetireTimeoutOutOfRange,
            "backend.af-packet.ports[0].rx.retire-timeout-ms",
            Some((1, 0)),
        ),
        (
            edited("retire-timeout-ms = 4", "retire-timeout-ms = 1001"),
            ValidationCode::BackendRetireTimeoutOutOfRange,
            "backend.af-packet.ports[0].rx.retire-timeout-ms",
            Some((u64::from(MAX_AF_PACKET_RETIRE_TIMEOUT_MS), 1_001)),
        ),
        (
            // 48 + 82 + 9014 = 9144 does not fit an 8 KiB RX block.
            two_ports("max-frame-len = 9014\n").replacen(
                "rx = { block-size = 65536",
                "rx = { block-size = 8192",
                1,
            ),
            ValidationCode::BackendBlockTooSmall,
            "backend.af-packet.ports[0].rx.block-size",
            Some((16_384, 8_192)),
        ),
        (
            // The TX slot of a 9014-byte frame is 16 KiB.
            two_ports("max-frame-len = 9014\n").replacen(
                "tx = { block-size = 65536",
                "tx = { block-size = 8192",
                1,
            ),
            ValidationCode::BackendBlockTooSmall,
            "backend.af-packet.ports[0].tx.block-size",
            Some((16_384, 8_192)),
        ),
        (
            // 4 MiB x 64 RX blocks are 256 MiB; any TX on top is too much.
            edited(
                "rx = { block-size = 65536, block-count = 8",
                "rx = { block-size = 4194304, block-count = 64",
            ),
            ValidationCode::BackendRingTooLarge,
            "backend.af-packet.ports[0].rx",
            Some((MAX_AF_PACKET_RING_BYTES_PER_PORT, (256 << 20) + 4 * 65_536)),
        ),
    ];
    for (text, code, path, bounds) in cases {
        let error = reject(&text);
        assert_eq!(error.code(), code, "{text}");
        assert_eq!(rendered(error.path().segments()), path, "{text}");
        assert_eq!(error.limit().zip(error.actual()), bounds, "{text}");
        let debug = format!("{error:?}");
        assert!(
            !debug.contains("nosuchif") && !debug.contains("eth"),
            "{debug}"
        );
    }

    // Total ring memory: four 256 MiB ports fit, a fifth does not.
    let big = |count: usize| {
        let mut text = format!("{}\n[backend]\nkind = \"af-packet\"\n", interfaces(count));
        for index in 0..count {
            text.push_str(
                &port(&format!("if{index}"))
                    .replacen(
                        "rx = { block-size = 65536, block-count = 8",
                        "rx = { block-size = 4194304, block-count = 63",
                        1,
                    )
                    .replacen(
                        "tx = { block-size = 65536, block-count = 4",
                        "tx = { block-size = 4194304, block-count = 1",
                        1,
                    ),
            );
        }
        text
    };
    let four = check(&big(4)).unwrap();
    assert_eq!(
        four.backend().af_packet().unwrap().ring_bytes(),
        MAX_AF_PACKET_RING_BYTES
    );
    let error = reject(&big(5));
    assert_eq!(error.code(), ValidationCode::BackendTotalRingTooLarge);
    assert_eq!(
        rendered(error.path().segments()),
        "backend.af-packet.ports[4].rx"
    );
    assert_eq!(
        error.limit().zip(error.actual()),
        Some((
            MAX_AF_PACKET_RING_BYTES,
            MAX_AF_PACKET_RING_BYTES + MAX_AF_PACKET_RING_BYTES_PER_PORT
        ))
    );
}

#[test]
fn af_packet_schema_is_exact_and_bounded() {
    // Unknown fields anywhere in the section are refused.
    for (text, path) in [
        (
            two_ports("max-frame = 1514\n"),
            "backend.af-packet".to_owned(),
        ),
        (
            edited(
                "retire-timeout-ms = 4 }",
                "retire-timeout-ms = 4, frame-size = 2048 }",
            ),
            "backend.af-packet.ports[0].rx".to_owned(),
        ),
        (
            edited(
                "tx = { block-size = 65536, block-count = 4 }",
                "tx = { block-size = 65536, block-count = 4, retire-timeout-ms = 1 }",
            ),
            "backend.af-packet.ports[0].tx".to_owned(),
        ),
        (
            edited("interface = \"if1\"\n", "interface = \"if1\"\nqueue = 0\n"),
            "backend.af-packet.ports[0]".to_owned(),
        ),
    ] {
        let diagnostic = parse(text.as_bytes()).expect_err("refused");
        assert!(
            matches!(
                diagnostic.code(),
                DiagnosticCode::UnknownField | DiagnosticCode::ForbiddenField
            ),
            "{text}: {:?}",
            diagnostic.code()
        );
        let shown = rendered(diagnostic.path().segments());
        assert!(shown.starts_with(&path), "{shown} vs {path}");
    }
    // Every ring field is required.
    let missing = edited(", retire-timeout-ms = 4", "");
    assert_eq!(
        parse(missing.as_bytes()).expect_err("missing").code(),
        DiagnosticCode::MissingField
    );
    // The port list is bounded like `[[backend.ports]]`.
    let mut text = format!("{}\n[backend]\nkind = \"af-packet\"\n", interfaces(1));
    for _ in 0..=MAX_BACKEND_PORTS {
        text.push_str(&port("if0"));
    }
    let diagnostic = parse(text.as_bytes()).expect_err("too long");
    assert_eq!(diagnostic.code(), DiagnosticCode::ListTooLong);
    assert_eq!(
        rendered(diagnostic.path().segments()),
        "backend.af-packet.ports"
    );
}

#[test]
fn af_packet_limits_accept_exact_boundaries() {
    for (head, from, to) in [
        (
            "max-frame-len = 590\n",
            "block-count = 8",
            "block-count = 8",
        ),
        (
            "max-frame-len = 9230\n",
            "block-count = 8",
            "block-count = 8",
        ),
        ("", "retire-timeout-ms = 4", "retire-timeout-ms = 1"),
        ("", "retire-timeout-ms = 4", "retire-timeout-ms = 1000"),
        ("", "block-count = 8", "block-count = 1"),
        ("", "rx = { block-size = 65536", "rx = { block-size = 4096"),
        ("", "tx = { block-size = 65536", "tx = { block-size = 4096"),
        (
            "",
            "rx = { block-size = 65536, block-count = 8",
            "rx = { block-size = 4194304, block-count = 63",
        ),
    ] {
        let text = two_ports(head).replacen(from, to, 1);
        assert!(check(&text).is_ok(), "{head} {to}");
    }
    // The largest block count, filling the per-port ring bound exactly.
    let full = two_ports("")
        .replacen(
            "rx = { block-size = 65536, block-count = 8",
            "rx = { block-size = 4096, block-count = 65535",
            1,
        )
        .replacen(
            "tx = { block-size = 65536, block-count = 4",
            "tx = { block-size = 4096, block-count = 1",
            1,
        );
    let config = check(&full).unwrap();
    let port = &config.backend().af_packet().unwrap().ports()[1]; // `if1`, the edited entry
    assert_eq!(
        port.rx().byte_len() + port.tx().byte_len(),
        MAX_AF_PACKET_RING_BYTES_PER_PORT
    );
    let counted = two_ports("").replacen(
        "tx = { block-size = 65536, block-count = 4",
        "tx = { block-size = 4096, block-count = 65536",
        1,
    );
    assert_eq!(
        reject(&counted).code(),
        ValidationCode::BackendRingTooLarge,
        "65536 blocks are accepted as a count but exceed the ring bound with RX"
    );
    assert_eq!(MIN_AF_PACKET_BLOCK_SIZE, 4_096);
    assert_eq!(MAX_AF_PACKET_BLOCK_SIZE, 4 << 20);
}

/// Every geometry the configuration accepts is one the AF_PACKET backend
/// accepts at a 4 KiB page, and a block one power of two below the
/// accepted minimum is refused by both: the derived frame slots and the
/// RX block minimum agree with `ruster-io-afpacket`'s own validator.
#[test]
fn af_packet_geometry_is_consistent_with_the_backend_validator() {
    const PAGE: usize = 4_096;
    let mut accepted = 0;
    for max_frame in [
        590_u32, 1_000, 1_500, 1_514, 1_518, 1_966, 1_967, 4_000, 9_014, 9_230,
    ] {
        for shift in 12..=17 {
            let block = 1_u32 << shift;
            let text = two_ports(&format!("max-frame-len = {max_frame}\n"))
                .replace("block-size = 65536", &format!("block-size = {block}"));
            let rx_backend = RingGeometry {
                block_size: block,
                block_count: 8,
                frame_size: 0,
                frame_count: 0,
                retire_timeout_ms: 4,
                private_size: 0,
                feature_flags: 0,
            };
            match check(&text) {
                Ok(config) => {
                    accepted += 1;
                    let packet = config.backend().af_packet().unwrap();
                    let ports: Vec<PortConfig> = packet
                        .ports()
                        .iter()
                        .enumerate()
                        .map(|(index, port)| {
                            let geometry = |ring: ruster_config::AfPacketRingV1| RingGeometry {
                                block_size: ring.block_size(),
                                block_count: ring.block_count(),
                                frame_size: ring.frame_size(),
                                frame_count: ring.frame_count(),
                                retire_timeout_ms: ring.retire_timeout_ms(),
                                private_size: 0,
                                feature_flags: 0,
                            };
                            PortConfig {
                                interface: port.interface(),
                                if_index: u32::try_from(index).unwrap() + 1,
                                rx: geometry(port.rx()),
                                tx: geometry(port.tx()),
                            }
                        })
                        .collect();
                    PacketConfig::new(&ports, PAGE, max_frame as usize)
                        .unwrap_or_else(|error| panic!("{max_frame} {block}: {error:?}"));
                }
                Err(error) => {
                    assert_eq!(error.code(), ValidationCode::BackendBlockTooSmall);
                    // The backend refuses this block for any frame slot
                    // that holds the frame.
                    let rx_frame = (82 + max_frame).div_ceil(16) * 16;
                    let tx_frame = (48 + max_frame).div_ceil(16) * 16;
                    let rx = RingGeometry {
                        frame_size: rx_frame.next_power_of_two().min(block),
                        frame_count: 8 * (block / rx_frame.next_power_of_two().min(block)),
                        ..rx_backend
                    }
                    .validate_rx(PAGE, max_frame as usize);
                    let tx = RingGeometry {
                        frame_size: tx_frame.next_power_of_two().min(block),
                        frame_count: 8 * (block / tx_frame.next_power_of_two().min(block)),
                        retire_timeout_ms: 0,
                        ..rx_backend
                    }
                    .validate_tx(PAGE, max_frame as usize);
                    assert!(rx.is_err() || tx.is_err(), "{max_frame} {block}");
                }
            }
        }
    }
    assert!(accepted > 30, "{accepted}");
}

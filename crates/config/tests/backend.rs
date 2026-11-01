//! `[backend]` schema (CONFIG-004) and AF_XDP backend validation
//! (CONFIG-005).

use ruster_config::{
    parse, validate, AfXdpModeV1, BackendKindV1, DiagnosticCode, ExistingXdpProgramV1, PathSegment,
    ValidatedBackendV1, ValidatedConfig, ValidatedConfigV1, ValidationCode, ValidationError,
    ValidationLimits, XdpAttachModeV1, MAX_AF_XDP_QUEUE_ID, MAX_AF_XDP_RING_ENTRIES,
    MAX_AF_XDP_UMEM_BYTES, MAX_AF_XDP_UMEM_BYTES_PER_PORT, MAX_BACKEND_PORTS,
    MIN_AF_XDP_RING_ENTRIES, MIN_AF_XDP_VISIBLE_FRAME_BYTES,
};
use ruster_core::IfId;
// The same types `ruster-io-xdp-native` re-exports as its native profile.
use ruster_io_xdp::native_profile::{
    BindMode, UmemConfig, SUPPORTED_ALIGNED_CHUNK_SIZES, XDP_COPY, XDP_PACKET_HEADROOM,
    XDP_USE_NEED_WAKEUP, XDP_ZEROCOPY,
};

const LIMITS: ValidationLimits = ValidationLimits {
    max_slots_per_table: 1 << 16,
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

/// One `[[backend.ports]]` entry with the documented example geometry.
fn port(interface: &str) -> String {
    format!(
        "\n[[backend.ports]]\ninterface = \"{interface}\"\nqueue = 0\nmode = \"copy\"\n\
         xdp-attach = \"native\"\n\
         rings = {{ fill = 2048, rx = 2048, tx = 2048, completion = 2048 }}\n\
         frame-size = 4096\nframe-count = 4608\ngenerated-frames = 512\n"
    )
}

/// Two interfaces, both bound; the ports are listed `if1` first.
fn two_ports() -> String {
    format!(
        "{}\n[backend]\nkind = \"af-xdp\"\n{}{}",
        interfaces(2),
        port("if1"),
        port("if0")
    )
}

/// `two_ports` with exactly one textual replacement of `from` (which must
/// occur once) in the first port entry.
fn edited(from: &str, to: &str) -> String {
    let text = two_ports();
    let first = text.find("[[backend.ports]]").unwrap();
    let second = text[first + 1..].find("[[backend.ports]]").unwrap() + first + 1;
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

fn reject(text: &str) -> ValidationError {
    match check(text) {
        Ok(_) => panic!("accepted"),
        Err(error) => error,
    }
}

#[test]
fn backend_section_is_optional_and_defaults_to_sim() {
    let fixture = include_str!("../../../fixtures/m1/router-v1.toml");
    let config = check(fixture).unwrap();
    assert_eq!(config.backend(), &ValidatedBackendV1::Sim);
    assert_eq!(config.backend().kind(), BackendKindV1::Sim);
    assert!(config.backend().af_xdp().is_none());

    for section in ["\n[backend]\n", "\n[backend]\nkind = \"sim\"\n"] {
        let config = check(&format!("{fixture}{section}")).unwrap();
        assert_eq!(config.backend(), &ValidatedBackendV1::Sim);
    }
    // `existing-xdp-program` is accepted (and meaningless) with `sim`.
    let config = check(&format!(
        "{fixture}\n[backend]\nexisting-xdp-program = \"refuse\"\n"
    ))
    .unwrap();
    assert_eq!(config.backend(), &ValidatedBackendV1::Sim);
}

#[test]
fn af_xdp_backend_validates_to_typed_native_profile() {
    let config = check(&two_ports()).unwrap();
    let af_xdp = config.backend().af_xdp().expect("af-xdp");
    assert_eq!(config.backend().kind(), BackendKindV1::AfXdp);
    assert_eq!(af_xdp.existing_program(), ExistingXdpProgramV1::Refuse);
    assert_eq!(af_xdp.umem_bytes(), 2 * 4608 * 4096);
    // Canonical IfId order regardless of source order.
    let ids: Vec<IfId> = af_xdp.ports().iter().map(|p| p.interface()).collect();
    assert_eq!(ids, [IfId(1), IfId(2)]);
    for port in af_xdp.ports() {
        assert_eq!(port.queue(), 0);
        assert_eq!(port.mode(), AfXdpModeV1::Copy);
        assert_eq!(port.attach(), XdpAttachModeV1::Native);
        assert_eq!(port.bind_flags().raw(), XDP_USE_NEED_WAKEUP | XDP_COPY);
        assert_eq!(port.bind_flags().mode(), BindMode::CopyRequired);
        assert!(!port.bind_flags().shared_umem());
        let rings = port.rings();
        assert_eq!(
            [rings.fill(), rings.rx(), rings.tx(), rings.completion()].map(|r| r.get()),
            [2048; 4]
        );
        let umem = port.umem();
        assert_eq!(umem, UmemConfig::new(4608, 4096, 0, 4096, 512, 0).unwrap());
        assert_eq!(umem.rx_frames(), 4096);
        assert_eq!(umem.generated_frames(), 512);
        assert_eq!(umem.visible_capacity(), 4096 - XDP_PACKET_HEADROOM);
    }

    // Every mode with native attach, copy with generic, and the
    // explicit spelling of every default.
    for (mode, attach, raw, bind) in [
        ("auto", "native", XDP_USE_NEED_WAKEUP, BindMode::Automatic),
        (
            "zero-copy",
            "native",
            XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
            BindMode::ZeroCopyRequired,
        ),
        (
            "copy",
            "generic",
            XDP_USE_NEED_WAKEUP | XDP_COPY,
            BindMode::CopyRequired,
        ),
    ] {
        let text = edited("mode = \"copy\"", &format!("mode = \"{mode}\""))
            .replacen(
                "xdp-attach = \"native\"",
                &format!("xdp-attach = \"{attach}\""),
                1,
            )
            .replacen(
                "kind = \"af-xdp\"\n",
                "kind = \"af-xdp\"\nexisting-xdp-program = \"refuse\"\n",
                1,
            )
            .replacen(
                "queue = 0\n",
                "queue = 0\nneed-wakeup = true\nheadroom = 0\n",
                1,
            );
        let config = check(&text).unwrap();
        let port = &config.backend().af_xdp().unwrap().ports()[1];
        assert_eq!(port.interface(), IfId(2));
        assert_eq!(port.bind_flags().raw(), raw, "{mode} {attach}");
        assert_eq!(port.bind_flags().mode(), bind);
        assert_eq!(port.mode().config_name(), mode);
        assert_eq!(port.attach().config_name(), attach);
    }
}

#[test]
fn backend_schema_is_exact_bounded_and_value_free() {
    let base = two_ports();
    let syntax = |text: &str| parse(text.as_bytes()).unwrap_err();
    for (from, to, code) in [
        (
            "kind = \"af-xdp\"",
            "kind = \"DO_NOT_ECHO_KIND\"",
            DiagnosticCode::InvalidType,
        ),
        (
            "kind = \"af-xdp\"",
            "kind = \"af-xdp\"\nexisting-xdp-program = \"DO_NOT_ECHO_REPLACE\"",
            DiagnosticCode::InvalidType,
        ),
        (
            "kind = \"af-xdp\"",
            "kind = \"af-xdp\"\nDO_NOT_ECHO_FIELD = 1",
            DiagnosticCode::UnknownField,
        ),
        (
            "mode = \"copy\"",
            "mode = \"DO_NOT_ECHO_MODE\"",
            DiagnosticCode::InvalidType,
        ),
        (
            "xdp-attach = \"native\"",
            "xdp-attach = \"DO_NOT_ECHO_SKB\"",
            DiagnosticCode::InvalidType,
        ),
        (
            "frame-size = 4096",
            "frame-size = 4096\nDO_NOT_ECHO_PORT_FIELD = 1",
            DiagnosticCode::UnknownField,
        ),
        (
            "completion = 2048 }",
            "completion = 2048, DO_NOT_ECHO_RING = 1 }",
            DiagnosticCode::UnknownField,
        ),
        (
            "frame-size = 4096",
            "frame-size = -1",
            DiagnosticCode::InvalidType,
        ),
        (
            "queue = 0",
            "queue = \"DO_NOT_ECHO_Q\"",
            DiagnosticCode::InvalidType,
        ),
        ("generated-frames = 512\n", "", DiagnosticCode::MissingField),
        (
            "queue = 0",
            "queue = 0\nqueue = 1",
            DiagnosticCode::DuplicateField,
        ),
    ] {
        assert!(base.contains(from), "{from:?}");
        let diagnostic = syntax(&base.replacen(from, to, 1));
        assert_eq!(diagnostic.code(), code, "{to:?}");
        assert!(!format!("{diagnostic:?}").contains("DO_NOT_ECHO"), "{to:?}");
    }
    let wrong = syntax(&base.replacen("frame-size = 4096", "frame-size = -1", 1));
    assert_eq!(
        rendered(wrong.path().segments()),
        "backend.ports[0].frame-size"
    );

    // A queue id is operator input only inside one `[[backend.ports]]`
    // entry; elsewhere `queue` stays a forbidden runtime field.
    for text in [
        base.replacen("kind = \"af-xdp\"", "kind = \"af-xdp\"\nqueue = 0", 1),
        format!("{base}\n[nat44]\nqueue = 0\n"),
        base.replacen("completion = 2048 }", "completion = 2048, queue = 0 }", 1),
    ] {
        assert_eq!(syntax(&text).code(), DiagnosticCode::ForbiddenField);
    }
    // The exemption needs the complete source path: `queue` under an
    // unknown key, at an alternate path, or spelled differently stays
    // forbidden (not merely an unknown field).
    for text in [
        base.replacen(
            "frame-size = 4096",
            "frame-size = 4096\nnested = { queue = 1 }",
            1,
        ),
        format!("{base}\n[[backend.x.ports]]\nqueue = 0\n"),
        format!("{base}\n[[Backend.ports]]\nqueue = 0\n"),
        format!("{base}\n[[backend.Ports]]\nqueue = 0\n"),
        // A sub-table of the last port entry.
        format!("{base}\n[backend.ports.extra]\nqueue = 0\n"),
        base.replacen("queue = 0", "Queue = 0", 1),
        base.replacen("queue = 0", "QUEUE = 0", 1),
    ] {
        let diagnostic = syntax(&text);
        assert_eq!(diagnostic.code(), DiagnosticCode::ForbiddenField, "{text}");
    }
    for field in ["queues", "queue-id", "umem", "workers"] {
        let text = base.replacen("queue = 0", &format!("queue = 0\n{field} = 1"), 1);
        assert_eq!(
            syntax(&text).code(),
            DiagnosticCode::ForbiddenField,
            "{field}"
        );
    }

    // The port list is bounded before semantic validation.
    let mut long = format!("{}\n[backend]\nkind = \"af-xdp\"\n", interfaces(1));
    for _ in 0..=MAX_BACKEND_PORTS {
        long.push_str(&port("if0"));
    }
    let diagnostic = syntax(&long);
    assert_eq!(diagnostic.code(), DiagnosticCode::ListTooLong);
    assert_eq!(rendered(diagnostic.path().segments()), "backend.ports");
    assert_eq!(diagnostic.limit(), Some(MAX_BACKEND_PORTS));
}

/// Document, expected code, rendered path, and `(limit, actual)` bounds.
type Case = (String, ValidationCode, &'static str, Option<(u64, u64)>);

#[test]
fn backend_validation_rejects_every_rule_with_a_value_free_path() {
    let max_headroom = 2048 - XDP_PACKET_HEADROOM - MIN_AF_XDP_VISIBLE_FRAME_BYTES;
    let cases: Vec<Case> = vec![
        (
            format!("{}\n[backend]\n{}", interfaces(2), port("if0")),
            ValidationCode::BackendPortsWithoutAfXdp,
            "backend.ports",
            None,
        ),
        (
            format!("{}\n[backend]\nkind = \"af-xdp\"\n", interfaces(2)),
            ValidationCode::BackendNoPorts,
            "backend.ports",
            None,
        ),
        (
            edited("interface = \"if1\"", "interface = \"nosuchif\""),
            ValidationCode::UnknownInterface,
            "backend.ports[0].interface",
            None,
        ),
        (
            format!(
                "{}\n[backend]\nkind = \"af-xdp\"\n{}",
                interfaces(2),
                port("if1")
            ),
            ValidationCode::BackendInterfaceUnbound,
            "interfaces[0].name",
            None,
        ),
        (
            edited("interface = \"if1\"", "interface = \"if0\""),
            ValidationCode::BackendDuplicateQueue,
            "backend.ports[1].queue",
            None,
        ),
        (
            edited("interface = \"if1\"", "interface = \"if0\"").replacen(
                "queue = 0",
                "queue = 3",
                1,
            ),
            ValidationCode::BackendMultipleQueuesPerInterface,
            "backend.ports[1].queue",
            None,
        ),
        (
            edited("queue = 0", &format!("queue = {}", MAX_AF_XDP_QUEUE_ID + 1)),
            ValidationCode::BackendQueueOutOfRange,
            "backend.ports[0].queue",
            Some((
                u64::from(MAX_AF_XDP_QUEUE_ID),
                u64::from(MAX_AF_XDP_QUEUE_ID) + 1,
            )),
        ),
        (
            edited("mode = \"copy\"", "mode = \"zero-copy\"").replacen(
                "xdp-attach = \"native\"",
                "xdp-attach = \"generic\"",
                1,
            ),
            ValidationCode::BackendModeRequiresNativeAttach,
            "backend.ports[0].mode",
            None,
        ),
        (
            edited("mode = \"copy\"", "mode = \"auto\"").replacen(
                "xdp-attach = \"native\"",
                "xdp-attach = \"generic\"",
                1,
            ),
            ValidationCode::BackendModeRequiresNativeAttach,
            "backend.ports[0].mode",
            None,
        ),
        (
            edited("queue = 0", "queue = 0\nneed-wakeup = false"),
            ValidationCode::BackendNeedWakeupRequired,
            "backend.ports[0].need-wakeup",
            None,
        ),
        (
            edited("fill = 2048", "fill = 2047"),
            ValidationCode::BackendRingNotPowerOfTwo,
            "backend.ports[0].rings.fill",
            None,
        ),
        (
            edited("rx = 2048", "rx = 0"),
            ValidationCode::BackendRingNotPowerOfTwo,
            "backend.ports[0].rings.rx",
            None,
        ),
        (
            edited("tx = 2048", "tx = 3072"),
            ValidationCode::BackendRingNotPowerOfTwo,
            "backend.ports[0].rings.tx",
            None,
        ),
        (
            edited("completion = 2048", "completion = 2049"),
            ValidationCode::BackendRingNotPowerOfTwo,
            "backend.ports[0].rings.completion",
            None,
        ),
        (
            edited(
                "rx = 2048",
                &format!("rx = {}", MIN_AF_XDP_RING_ENTRIES / 2),
            ),
            ValidationCode::BackendRingOutOfRange,
            "backend.ports[0].rings.rx",
            Some((
                u64::from(MIN_AF_XDP_RING_ENTRIES),
                u64::from(MIN_AF_XDP_RING_ENTRIES / 2),
            )),
        ),
        (
            edited(
                "rx = 2048",
                &format!("rx = {}", MAX_AF_XDP_RING_ENTRIES * 2),
            ),
            ValidationCode::BackendRingOutOfRange,
            "backend.ports[0].rings.rx",
            Some((
                u64::from(MAX_AF_XDP_RING_ENTRIES),
                u64::from(MAX_AF_XDP_RING_ENTRIES * 2),
            )),
        ),
        (
            edited("completion = 2048", "completion = 1024"),
            ValidationCode::BackendCompletionRingTooSmall,
            "backend.ports[0].rings.completion",
            Some((2048, 1024)),
        ),
        (
            edited("frame-size = 4096", "frame-size = 8192"),
            ValidationCode::BackendFrameSizeUnsupported,
            "backend.ports[0].frame-size",
            None,
        ),
        (
            edited("frame-size = 4096", "frame-size = 3072"),
            ValidationCode::BackendFrameSizeUnsupported,
            "backend.ports[0].frame-size",
            None,
        ),
        (
            edited(
                "frame-size = 4096",
                &format!("frame-size = 2048\nheadroom = {}", max_headroom + 1),
            ),
            ValidationCode::BackendHeadroomTooLarge,
            "backend.ports[0].headroom",
            Some((u64::from(max_headroom), u64::from(max_headroom) + 1)),
        ),
        (
            edited(
                "frame-size = 4096",
                "frame-size = 2048\nheadroom = 4294967295",
            ),
            ValidationCode::BackendHeadroomTooLarge,
            "backend.ports[0].headroom",
            Some((u64::from(max_headroom), u64::from(u32::MAX))),
        ),
        (
            edited("generated-frames = 512", "generated-frames = 0"),
            ValidationCode::BackendGeneratedFramesZero,
            "backend.ports[0].generated-frames",
            None,
        ),
        (
            edited("frame-count = 4608", "frame-count = 4607"),
            ValidationCode::BackendFrameCountTooSmall,
            "backend.ports[0].frame-count",
            Some((4608, 4607)),
        ),
        (
            edited("generated-frames = 512", "generated-frames = 4294967295"),
            ValidationCode::BackendFrameCountTooSmall,
            "backend.ports[0].frame-count",
            Some((4096 + u64::from(u32::MAX), 4608)),
        ),
        (
            edited("frame-count = 4608", "frame-count = 65537"),
            ValidationCode::BackendUmemTooLarge,
            "backend.ports[0].frame-count",
            Some((MAX_AF_XDP_UMEM_BYTES_PER_PORT, 65537 * 4096)),
        ),
        (
            edited("frame-count = 4608", "frame-count = 4294967295"),
            ValidationCode::BackendUmemTooLarge,
            "backend.ports[0].frame-count",
            Some((MAX_AF_XDP_UMEM_BYTES_PER_PORT, u64::from(u32::MAX) * 4096)),
        ),
    ];
    for (text, code, path, bounds) in cases {
        let error = reject(&text);
        assert_eq!(error.code(), code, "{path}");
        assert_eq!(rendered(error.path().segments()), path, "{code:?}");
        assert_eq!(error.limit().zip(error.actual()), bounds, "{code:?}");
        assert!(code.code().starts_with("BACKEND_") || code == ValidationCode::UnknownInterface);
        let debug = format!("{error:?}");
        assert!(
            !debug.contains("nosuchif") && !debug.contains("eth"),
            "{debug}"
        );
    }

    // Total UMEM across sockets: four 256 MiB sockets fit, a fifth does
    // not.
    let big = |count: usize| {
        let mut text = format!("{}\n[backend]\nkind = \"af-xdp\"\n", interfaces(count));
        for index in 0..count {
            text.push_str(&port(&format!("if{index}")).replacen(
                "frame-count = 4608",
                "frame-count = 65536",
                1,
            ));
        }
        text
    };
    let four = check(&big(4)).unwrap();
    assert_eq!(
        four.backend().af_xdp().unwrap().umem_bytes(),
        MAX_AF_XDP_UMEM_BYTES
    );
    let error = reject(&big(5));
    assert_eq!(error.code(), ValidationCode::BackendTotalUmemTooLarge);
    assert_eq!(
        rendered(error.path().segments()),
        "backend.ports[4].frame-count"
    );
    assert_eq!(
        error.limit().zip(error.actual()),
        Some((
            MAX_AF_XDP_UMEM_BYTES,
            MAX_AF_XDP_UMEM_BYTES + MAX_AF_XDP_UMEM_BYTES_PER_PORT
        ))
    );
}

#[test]
fn backend_limits_accept_exact_boundaries() {
    let max_headroom = 2048 - XDP_PACKET_HEADROOM - MIN_AF_XDP_VISIBLE_FRAME_BYTES;
    for text in [
        // frame-count == fill + tx + generated-frames.
        edited("frame-count = 4608", "frame-count = 4608"),
        edited(
            "rings = { fill = 2048, rx = 2048, tx = 2048, completion = 2048 }",
            &format!(
                "rings = {{ fill = {min}, rx = {min}, tx = {min}, completion = {min} }}",
                min = MIN_AF_XDP_RING_ENTRIES
            ),
        ),
        edited(
            "rings = { fill = 2048, rx = 2048, tx = 2048, completion = 2048 }\n\
             frame-size = 4096\nframe-count = 4608",
            &format!(
                "rings = {{ fill = {max}, rx = {max}, tx = {max}, completion = {max} }}\n\
                 frame-size = 4096\nframe-count = 65536",
                max = MAX_AF_XDP_RING_ENTRIES
            ),
        ),
        edited(
            "frame-size = 4096",
            &format!("frame-size = 2048\nheadroom = {max_headroom}"),
        ),
        edited("queue = 0", &format!("queue = {MAX_AF_XDP_QUEUE_ID}")),
        // A larger Completion ring than TX ring is fine, and the Completion
        // ring is not compared with the RX ring.
        edited("completion = 2048", "completion = 4096"),
        edited("rx = 2048", "rx = 4096"),
        edited("frame-count = 4608", "frame-count = 65536"),
    ] {
        let config = check(&text).unwrap();
        let port = &config.backend().af_xdp().unwrap().ports()[1];
        let umem = port.umem();
        assert!(umem.visible_capacity() >= MIN_AF_XDP_VISIBLE_FRAME_BYTES);
        let rings = port.rings();
        assert!(umem.rx_frames() >= rings.fill().get() + rings.tx().get());
        assert!(umem.byte_len() <= MAX_AF_XDP_UMEM_BYTES_PER_PORT);
    }
}

/// The configuration's frame-size/headroom rules are a strict, documented
/// tightening of the native profile: everything they accept the native
/// validator accepts, and the only extra rejection is the visible-frame
/// floor.
#[test]
fn backend_geometry_is_consistent_with_the_native_profile() {
    assert!(SUPPORTED_ALIGNED_CHUNK_SIZES
        .iter()
        .all(|size| *size >= XDP_PACKET_HEADROOM + MIN_AF_XDP_VISIBLE_FRAME_BYTES));
    for frame_size in [0, 1024, 2047, 2048, 3072, 4096, 4097, 8192, u32::MAX] {
        for headroom in [0, 1, 278, 279, 1000, 2326, 2327, 3839, 3840, u32::MAX] {
            let text = edited(
                "frame-size = 4096",
                &format!("frame-size = {frame_size}\nheadroom = {headroom}"),
            );
            let native = UmemConfig::new(4608, frame_size, headroom, 4096, 512, 0);
            match check(&text) {
                Ok(config) => {
                    let port = &config.backend().af_xdp().unwrap().ports()[1];
                    assert_eq!(Ok(port.umem()), native, "{frame_size} {headroom}");
                    assert!(port.umem().visible_capacity() >= MIN_AF_XDP_VISIBLE_FRAME_BYTES);
                }
                Err(error) => {
                    let floor = native
                        .is_ok_and(|umem| umem.visible_capacity() < MIN_AF_XDP_VISIBLE_FRAME_BYTES);
                    assert!(native.is_err() || floor, "{frame_size} {headroom}");
                    assert!(
                        matches!(
                            error.code(),
                            ValidationCode::BackendFrameSizeUnsupported
                                | ValidationCode::BackendHeadroomTooLarge
                                | ValidationCode::BackendUmemTooLarge
                        ),
                        "{frame_size} {headroom}: {error:?}"
                    );
                }
            }
        }
    }
}

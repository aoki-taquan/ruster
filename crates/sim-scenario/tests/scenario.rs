use std::num::NonZeroU64;
use std::path::Path;

use ruster_core::{
    internet_checksum, validate_arp, validate_ipv4_frame, ArpOpcode, ConsumeReason, DropReason,
};
use ruster_sim_scenario::{
    parse_scenario, ApplyOutcome, FrameKind, PathSegment, ScenarioErrorCode as Code, Step,
    MAX_EXPECTED_TX, MAX_FRAME_LEN, MAX_SCENARIO_BYTES, MAX_STEPS, MAX_TICKS_PER_STEP,
    MAX_TOTAL_TICKS,
};

const HEAD: &str = r#"
schema = "ruster-scenario/v1"
seed = 12345
config = "configs/./v1.toml"
"#;

const ETH: &str = r#"eth = { src = "02:00:00:00:00:10", dst = "02:00:00:00:00:01" }"#;
const IP: &str = r#"ip = { src = "192.0.2.10", dst = "198.51.100.20" }"#;

fn full_scenario() -> String {
    format!(
        r#"{HEAD}
start-ms = 100

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "raw", hex = "ffffffffffff 020000000010 0806" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "ethernet", {ETH}, ether-type = 0x88b5, payload-ascii = "hi" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "arp", eth = {{ src = "02:00:00:00:00:10", dst = "ff:ff:ff:ff:ff:ff" }}, op = "request", sender-mac = "02:00:00:00:00:10", sender-ip = "192.0.2.10", target-ip = "192.0.2.1" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "arp", {ETH}, op = "reply", sender-mac = "02:00:00:00:00:10", sender-ip = "192.0.2.10", target-mac = "02:00:00:00:00:01", target-ip = "192.0.2.1" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "ipv4", {ETH}, ip = {{ src = "192.0.2.10", dst = "198.51.100.20", ttl = 9, id = 77, df = false, tos = 4 }}, protocol = 47, payload-hex = "0001" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "icmp-echo", {ETH}, {IP}, op = "request", id = 1, seq = 2, payload-ascii = "ping" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "icmp-echo", {ETH}, {IP}, op = "reply" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "udp", {ETH}, {IP}, src-port = 40000, dst-port = 53, payload-hex = "abcdef" }}

[[step]]
kind = "inject"
interface = "lan"
frame = {{ kind = "tcp", {ETH}, {IP}, src-port = 40001, dst-port = 80, seq = 1000, ack = 2000, flags = ["syn", "ack", "fin", "rst", "psh"], window = 512, payload-ascii = "x" }}

[[step]]
kind = "tick"
advance-ms = 5
ticks = 3

[[step]]
kind = "tick"
at-ms = 200

[[step]]
kind = "tick"

[[step]]
kind = "apply"
config = "configs/v2.toml"
outcome = "applied"

[[step]]
kind = "apply"
config = "invalid.toml"
outcome = "rejected"

[[step]]
kind = "expect"
generation = 2
tx = [{{ interface = "wan", frame = {{ kind = "udp", {ETH}, {IP}, src-port = 1, dst-port = 2, zero-checksum = true }} }}]
drops = [{{ reason = "ROUTE_MISS", count = 3 }}, {{ reason = "UNSUPPORTED_ETHERTYPE", count = 1 }}]
consumes = [{{ reason = "ARP_CONTROL", count = 2 }}]

[[step]]
kind = "expect"
tx = []

[[step]]
kind = "hold"
"#
    )
}

fn parse(
    source: &str,
) -> Result<ruster_sim_scenario::Scenario, ruster_sim_scenario::ScenarioError> {
    parse_scenario(source.as_bytes(), Path::new("/scenarios/m1"))
}

fn reject(source: &str) -> Code {
    parse(source).expect_err("scenario must be rejected").code()
}

fn step(body: &str) -> String {
    format!("{HEAD}\n[[step]]\n{body}\n")
}

fn inject(frame: &str) -> String {
    step(&format!(
        "kind = \"inject\"\ninterface = \"lan\"\nframe = {{ {frame} }}"
    ))
}

/// Independent RFC 1071 one's-complement sum, used only to check builders.
fn ones_complement(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let word = u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        sum += word;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn pseudo_header_sum(frame: &[u8]) -> u16 {
    let ip = &frame[14..34];
    let segment = &frame[34..];
    let mut covered = Vec::new();
    covered.extend_from_slice(&ip[12..20]);
    covered.extend_from_slice(&[0, ip[9]]);
    covered.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    covered.extend_from_slice(segment);
    ones_complement(&covered)
}

fn injected(scenario: &ruster_sim_scenario::Scenario) -> Vec<&ruster_sim_scenario::Frame> {
    scenario
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Inject { frame, .. } => Some(frame),
            _ => None,
        })
        .collect()
}

#[test]
fn scenario_happy_path_covers_every_step_and_frame_kind() {
    let scenario = parse(&full_scenario()).expect("valid scenario");
    assert_eq!(scenario.seed.get(), 12345);
    assert_eq!(scenario.start_ms, 100);
    assert_eq!(scenario.config.relative(), Path::new("configs/v1.toml"));
    assert_eq!(
        scenario.config.resolved(),
        Path::new("/scenarios/m1/configs/v1.toml")
    );
    assert!(scenario.holds());
    let kinds: Vec<_> = injected(&scenario)
        .iter()
        .map(|frame| frame.kind())
        .collect();
    assert_eq!(
        kinds,
        [
            FrameKind::Raw,
            FrameKind::Ethernet,
            FrameKind::Arp,
            FrameKind::Arp,
            FrameKind::Ipv4,
            FrameKind::IcmpEcho,
            FrameKind::IcmpEcho,
            FrameKind::Udp,
            FrameKind::Tcp,
        ]
    );
    match &scenario.steps[0] {
        Step::Inject { interface, frame } => {
            assert_eq!(interface.as_str(), "lan");
            assert_eq!(
                frame.bytes(),
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 0x10, 8, 6]
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        scenario.steps[9],
        Step::Tick {
            at_ms: 105,
            ticks: 3
        }
    );
    assert_eq!(
        scenario.steps[10],
        Step::Tick {
            at_ms: 200,
            ticks: 1
        }
    );
    assert_eq!(
        scenario.steps[11],
        Step::Tick {
            at_ms: 200,
            ticks: 1
        }
    );
    match (&scenario.steps[12], &scenario.steps[13]) {
        (
            Step::Apply {
                config: v2,
                outcome: ApplyOutcome::Applied,
            },
            Step::Apply {
                config: invalid,
                outcome: ApplyOutcome::Rejected,
            },
        ) => {
            assert_eq!(v2.resolved(), Path::new("/scenarios/m1/configs/v2.toml"));
            assert_eq!(invalid.relative(), Path::new("invalid.toml"));
        }
        other => panic!("unexpected {other:?}"),
    }
    match &scenario.steps[14] {
        Step::Expect(expect) => {
            assert_eq!(expect.generation, NonZeroU64::new(2));
            let tx = expect.tx.as_ref().expect("tx");
            assert_eq!(tx.len(), 1);
            assert_eq!(tx[0].interface.as_str(), "wan");
            assert_eq!(&tx[0].frame.bytes()[40..42], [0, 0], "zero checksum kept");
            assert_eq!(
                expect.drops,
                [
                    (DropReason::RouteMiss, 3),
                    (DropReason::UnsupportedEtherType, 1)
                ]
            );
            assert_eq!(expect.consumes, [(ConsumeReason::ArpControl, 2)]);
        }
        other => panic!("unexpected {other:?}"),
    }
    match &scenario.steps[15] {
        Step::Expect(expect) => assert_eq!(expect.tx, Some(Vec::new())),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(scenario.steps[16], Step::Hold);
    assert!(
        !format!("{scenario:?}").contains("12345"),
        "seed is redacted"
    );
}

#[test]
fn built_frames_pass_core_validation_and_independent_checksums() {
    let scenario = parse(&full_scenario()).expect("valid scenario");
    let frames = injected(&scenario);

    let request = validate_arp(frames[2].bytes()).expect("arp request");
    assert_eq!(request.opcode, ArpOpcode::Request);
    assert_eq!(frames[2].bytes().len(), 42);
    assert_eq!(
        &frames[2].bytes()[32..38],
        [0; 6],
        "target MAC defaults to zero"
    );
    let reply = validate_arp(frames[3].bytes()).expect("arp reply");
    assert_eq!(reply.opcode, ArpOpcode::Reply);
    assert_eq!(frames[1].bytes()[12..], [0x88, 0xb5, b'h', b'i']);

    for frame in &frames[4..] {
        let bytes = frame.bytes();
        let ipv4 = validate_ipv4_frame(bytes).expect("core accepts IPv4 header");
        assert_eq!(ipv4.total_len, bytes.len() - 14);
        assert_eq!(ones_complement(&bytes[14..34]), 0, "IPv4 header checksum");
        assert_eq!(internet_checksum(&bytes[14..34]), 0);
    }
    let generic = frames[4].bytes();
    assert_eq!(
        generic[14..22],
        [0x45, 4, 0, 22, 0, 77, 0, 0],
        "ver/ihl, tos, length, id, DF clear"
    );
    assert_eq!(generic[22..24], [9, 47]);

    for echo in &frames[5..7] {
        assert_eq!(ones_complement(&echo.bytes()[34..]), 0, "ICMPv4 checksum");
    }
    assert_eq!(frames[5].bytes()[34], 8);
    assert_eq!(frames[6].bytes()[34], 0);
    assert_eq!(frames[5].bytes()[20..22], [0x40, 0], "DF default");

    let udp = frames[7].bytes();
    assert_eq!(udp[23], 17);
    assert_eq!(udp[38..40], [0, 11], "UDP length");
    assert_eq!(pseudo_header_sum(udp), 0, "UDP pseudo-header checksum");

    let tcp = frames[8].bytes();
    assert_eq!(tcp[23], 6);
    assert_eq!(tcp[38..46], [0, 0, 0x03, 0xe8, 0, 0, 0x07, 0xd0]);
    assert_eq!(tcp[46], 0x50, "data offset 5, no options");
    assert_eq!(tcp[47], 0x1f, "FIN|SYN|RST|PSH|ACK");
    assert_eq!(tcp[48..50], [2, 0], "window");
    assert_eq!(pseudo_header_sum(tcp), 0, "TCP pseudo-header checksum");
}

#[test]
fn builders_match_hand_computed_rfc_vectors() {
    // RFC 1071 §3 numerical example: one's-complement sum 0xddf2.
    assert_eq!(
        internet_checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
        !0xddf2
    );

    // Classic IPv4 header example 4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7.
    let source = inject(&format!(
        r#"kind = "udp", {ETH}, ip = {{ src = "192.168.0.1", dst = "192.168.0.199", id = 0 }}, src-port = 1, dst-port = 2, payload-hex = "{}""#,
        "00".repeat(115 - 28)
    ));
    let header = frame_bytes(&source);
    assert_eq!(
        header[14..34],
        [
            0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8,
            0, 0xc7
        ]
    );

    // RFC 768 checksum computed by hand over pseudo-header + header + "abc".
    let udp = frame_bytes(&inject(&format!(
        r#"kind = "udp", {ETH}, ip = {{ src = "192.0.2.1", dst = "198.51.100.1" }}, src-port = 40000, dst-port = 53, payload-ascii = "abc""#
    )));
    assert_eq!(udp[40..42], [0xb2, 0xc9]);

    // RFC 793 checksum by hand for a bare SYN, seq 1, window 65535.
    let tcp = frame_bytes(&inject(&format!(
        r#"kind = "tcp", {ETH}, ip = {{ src = "10.0.0.1", dst = "10.0.0.2" }}, src-port = 1234, dst-port = 80, seq = 1, flags = ["syn"]"#
    )));
    assert_eq!(tcp[47], 0x02);
    assert_eq!(tcp[50..52], [0x96, 0xbd]);

    // RFC 792 echo checksum by hand: type 8, id 1, seq 1, data "ping".
    let echo = frame_bytes(&inject(&format!(
        r#"kind = "icmp-echo", {ETH}, {IP}, op = "request", id = 1, seq = 1, payload-ascii = "ping""#
    )));
    assert_eq!(echo[36..38], [0x19, 0x2d]);
}

fn frame_bytes(source: &str) -> Vec<u8> {
    let scenario = parse(source).expect("valid frame scenario");
    match &scenario.steps[0] {
        Step::Inject { frame, .. } => frame.bytes().to_vec(),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn udp_computed_zero_checksum_is_transmitted_as_all_ones() {
    let base = frame_bytes(&inject(&format!(
        r#"kind = "udp", {ETH}, {IP}, src-port = 7, dst-port = 9, payload-hex = "0000""#
    )));
    let checksum = u16::from_be_bytes([base[40], base[41]]);
    // Adding the old checksum as data makes the one's-complement sum 0xffff,
    // whose complement 0 must be sent as 0xffff (RFC 768).
    let forced = frame_bytes(&inject(&format!(
        r#"kind = "udp", {ETH}, {IP}, src-port = 7, dst-port = 9, payload-hex = "{checksum:04x}""#
    )));
    assert_eq!(forced[40..42], [0xff, 0xff]);
    assert_eq!(pseudo_header_sum(&forced), 0);
}

#[test]
fn identical_input_yields_identical_model_and_bytes() {
    let source = full_scenario();
    let first = parse(&source).expect("valid");
    let second = parse(&source).expect("valid");
    assert_eq!(first, second);
    let first_bytes: Vec<Vec<u8>> = injected(&first)
        .iter()
        .map(|f| f.bytes().to_vec())
        .collect();
    let second_bytes: Vec<Vec<u8>> = injected(&second)
        .iter()
        .map(|f| f.bytes().to_vec())
        .collect();
    assert_eq!(first_bytes, second_bytes);
    assert_eq!(
        first_bytes[7],
        [
            2,
            0,
            0,
            0,
            0,
            1,
            2,
            0,
            0,
            0,
            0,
            0x10,
            8,
            0,
            0x45,
            0,
            0,
            31,
            0,
            0,
            0x40,
            0,
            64,
            17,
            first_bytes[7][24],
            first_bytes[7][25],
            192,
            0,
            2,
            10,
            198,
            51,
            100,
            20,
            0x9c,
            0x40,
            0,
            53,
            0,
            11,
            first_bytes[7][40],
            first_bytes[7][41],
            0xab,
            0xcd,
            0xef
        ]
    );
}

#[test]
fn every_rejection_class_is_typed() {
    let cases: Vec<(String, Code)> = vec![
        ("schema = \"ruster-scenario/v1\"\nseed = 1\nconfig = \"a\"\nconfig = \"b\"\n".into(), Code::DuplicateField),
        ("seed = 1\nconfig = \"a\"\n".into(), Code::MissingSchema),
        ("schema = \"ruster-scenario/v2\"\nseed = 1\nconfig = \"a\"\n".into(), Code::UnsupportedSchema),
        ("schema = 1\nseed = 1\nconfig = \"a\"\n".into(), Code::UnsupportedSchema),
        ("schema = \"ruster-scenario/v1\"\nseed = 1\nconfig = \"a\"\nextra = 1\n".into(), Code::UnknownField),
        ("schema = \"ruster-scenario/v1\"\nseed = 1\n".into(), Code::MissingField),
        ("schema = \"ruster-scenario/v1\"\nseed = -1\nconfig = \"a\"\n".into(), Code::InvalidType),
        ("schema = = 1".into(), Code::InvalidToml),
        (step("kind = \"teleport\""), Code::UnknownKind),
        (step("interface = \"lan\""), Code::MissingField),
        (step("kind = \"tick\"\nbogus = 1"), Code::UnknownField),
        (inject("kind = \"raw\", hex = \"00\", extra = 1"), Code::UnknownField),
        (inject("kind = \"jumbo\""), Code::UnknownKind),
        (inject(&format!("kind = \"udp\", {ETH}, ip = {{ src = \"192.0.2.1\", dst = \"192.0.2.2\", ttl = 300 }}, src-port = 1, dst-port = 2")), Code::InvalidType),
        (HEAD.replace("configs/./v1.toml", "/etc/v1.toml"), Code::AbsolutePath),
        (HEAD.replace("configs/./v1.toml", "configs/../../v1.toml"), Code::PathEscapesBase),
        (HEAD.replace("configs/./v1.toml", "a/../b.toml"), Code::PathEscapesBase),
        (HEAD.replace("configs/./v1.toml", "./."), Code::InvalidPath),
        (HEAD.replace("configs/./v1.toml", ""), Code::InvalidPath),
        (step("kind = \"apply\"\nconfig = \"../x.toml\"\noutcome = \"applied\""), Code::PathEscapesBase),
        (step("kind = \"apply\"\nconfig = \"x.toml\"\noutcome = \"maybe\""), Code::UnknownKind),
        (step("kind = \"inject\"\ninterface = \"\"\nframe = { kind = \"raw\", hex = \"\" }"), Code::InvalidInterfaceName),
        (step("kind = \"inject\"\ninterface = \"l an\"\nframe = { kind = \"raw\", hex = \"\" }"), Code::InvalidInterfaceName),
        (inject("kind = \"ethernet\", eth = { src = \"02:00:00:00:00\", dst = \"02:00:00:00:00:01\" }, ether-type = 1"), Code::InvalidMacAddress),
        (inject("kind = \"ethernet\", eth = { src = \"02:00:00:00:00:0g\", dst = \"02:00:00:00:00:01\" }, ether-type = 1"), Code::InvalidMacAddress),
        (inject("kind = \"ethernet\", eth = { src = \"02:00:00:00:00:01:02\", dst = \"02:00:00:00:00:01\" }, ether-type = 1"), Code::InvalidMacAddress),
        (inject(&format!("kind = \"udp\", {ETH}, ip = {{ src = \"192.0.2.01\", dst = \"192.0.2.2\" }}, src-port = 1, dst-port = 2")), Code::InvalidIpv4Address),
        (inject("kind = \"raw\", hex = \"abc\""), Code::InvalidHex),
        (inject("kind = \"raw\", hex = \"zz\""), Code::InvalidHex),
        (inject(&format!("kind = \"udp\", {ETH}, {IP}, src-port = 1, dst-port = 2, payload-ascii = \"tab\\there\"")), Code::InvalidAscii),
        (inject(&format!("kind = \"udp\", {ETH}, {IP}, src-port = 1, dst-port = 2, payload-ascii = \"a\", payload-hex = \"00\"")), Code::ConflictingPayload),
        (step("kind = \"tick\"\nadvance-ms = 1\nat-ms = 2"), Code::ConflictingTime),
        (format!("{HEAD}start-ms = 10\n[[step]]\nkind = \"tick\"\nat-ms = 9\n"), Code::TimeRegression),
        (step("kind = \"tick\"\nticks = 0"), Code::TickCountOutOfRange),
        (inject(&format!("kind = \"udp\", {ETH}, ip = {{ src = \"192.0.2.1\", dst = \"192.0.2.2\", fragment-offset = 8192 }}, src-port = 1, dst-port = 2")), Code::FragmentOffsetOutOfRange),
        (inject(&format!("kind = \"tcp\", {ETH}, {IP}, src-port = 1, dst-port = 2, flags = [\"syn\", \"syn\"]")), Code::DuplicateTcpFlag),
        (inject(&format!("kind = \"tcp\", {ETH}, {IP}, src-port = 1, dst-port = 2, flags = [\"urg\"]")), Code::UnknownKind),
        (step("kind = \"expect\"\ndrops = [{ reason = \"NOT_A_REASON\", count = 1 }]"), Code::UnknownReason),
        (step("kind = \"expect\"\nconsumes = [{ reason = \"ARP_CONTROL\", count = 1 }, { reason = \"ARP_CONTROL\", count = 2 }]"), Code::DuplicateReason),
        (step("kind = \"expect\""), Code::EmptyExpectation),
        (step("kind = \"expect\"\ngeneration = 0"), Code::ZeroGeneration),
        (format!("{HEAD}[[step]]\nkind = \"hold\"\n[[step]]\nkind = \"tick\"\n"), Code::HoldNotLast),
        (step("kind = \"hold\"\nextra = 1"), Code::UnknownField),
    ];
    for (source, expected) in cases {
        assert_eq!(reject(&source), expected, "source:\n{source}");
    }
    assert_eq!(
        parse_scenario(&[0xff, 0xfe], Path::new("."))
            .unwrap_err()
            .code(),
        Code::InvalidUtf8
    );
}

#[test]
fn time_overflow_is_typed() {
    let source = format!(
        "{HEAD}start-ms = {}\n[[step]]\nkind = \"tick\"\nadvance-ms = {}\n[[step]]\nkind = \"tick\"\nadvance-ms = {}\n",
        i64::MAX,
        i64::MAX,
        2
    );
    // start + MAX fits u64; the second advance overflows.
    let error = parse(&source).unwrap_err();
    assert_eq!(error.code(), Code::TimeOverflow);
    assert_eq!(
        error.path(),
        [
            PathSegment::Field("step"),
            PathSegment::Index(1),
            PathSegment::Field("advance-ms")
        ]
    );
}

#[test]
fn errors_are_value_free() {
    let secret = "SECRETVALUE";
    let cases = [
        format!("schema = \"ruster-scenario/v1\"\nseed = 1\nconfig = \"a\"\n{secret} = 1\n"),
        HEAD.replace("configs/./v1.toml", &format!("/{secret}")),
        inject(&format!("kind = \"raw\", hex = \"{secret}\"")),
        step(&format!(
            "kind = \"expect\"\ndrops = [{{ reason = \"{secret}\", count = 1 }}]"
        )),
        step(&format!("kind = \"{secret}\"")),
        format!("schema = \"{secret}\"\n"),
        format!("{secret} = = ="),
    ];
    for source in cases {
        let error = parse(&source).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(!rendered.contains("scenarios"), "{rendered}");
    }
}

#[test]
fn size_step_frame_and_tick_limits_are_enforced() {
    let mut big = HEAD.to_owned();
    big.push_str(&format!("# {}\n", "x".repeat(MAX_SCENARIO_BYTES)));
    let error = parse(&big).unwrap_err();
    assert_eq!(error.code(), Code::InputTooLarge);
    assert_eq!(error.limit(), Some(MAX_SCENARIO_BYTES as u64));

    let ticks = |count: usize| {
        let mut source = HEAD.to_owned();
        for _ in 0..count {
            source.push_str("[[step]]\nkind = \"tick\"\n");
        }
        source
    };
    assert_eq!(parse(&ticks(MAX_STEPS)).unwrap().steps.len(), MAX_STEPS);
    let error = parse(&ticks(MAX_STEPS + 1)).unwrap_err();
    assert_eq!(error.code(), Code::ListTooLong);
    assert_eq!(error.path(), [PathSegment::Field("step")]);
    assert_eq!(error.actual(), Some(MAX_STEPS as u64 + 1));

    let raw = |len: usize| inject(&format!("kind = \"raw\", hex = \"{}\"", "00".repeat(len)));
    assert_eq!(frame_bytes(&raw(MAX_FRAME_LEN)).len(), MAX_FRAME_LEN);
    assert_eq!(reject(&raw(MAX_FRAME_LEN + 1)), Code::FrameTooLong);
    let udp = |len: usize| {
        inject(&format!(
            "kind = \"udp\", {ETH}, {IP}, src-port = 1, dst-port = 2, payload-hex = \"{}\"",
            "00".repeat(len)
        ))
    };
    assert_eq!(frame_bytes(&udp(MAX_FRAME_LEN - 42)).len(), MAX_FRAME_LEN);
    let error = parse(&udp(MAX_FRAME_LEN - 41)).unwrap_err();
    assert_eq!(error.code(), Code::FrameTooLong);
    assert_eq!(error.actual(), Some(MAX_FRAME_LEN as u64 + 1));

    let per_step = |count: u32| step(&format!("kind = \"tick\"\nticks = {count}"));
    assert!(parse(&per_step(MAX_TICKS_PER_STEP)).is_ok());
    assert_eq!(
        reject(&per_step(MAX_TICKS_PER_STEP + 1)),
        Code::TickCountOutOfRange
    );
    let steps_needed = (MAX_TOTAL_TICKS / u64::from(MAX_TICKS_PER_STEP)) as usize;
    let mut total = HEAD.to_owned();
    for _ in 0..=steps_needed {
        total.push_str(&format!(
            "[[step]]\nkind = \"tick\"\nticks = {MAX_TICKS_PER_STEP}\n"
        ));
    }
    assert_eq!(reject(&total), Code::TooManyTicks);

    let mut tx = String::from("kind = \"expect\"\ntx = [");
    for _ in 0..=MAX_EXPECTED_TX {
        tx.push_str("{ interface = \"wan\", frame = { kind = \"raw\", hex = \"\" } },");
    }
    tx.push(']');
    assert_eq!(reject(&step(&tx)), Code::ListTooLong);
}

#[test]
fn rejection_paths_name_schema_fields_and_indices() {
    let source = format!(
        "{HEAD}[[step]]\nkind = \"tick\"\n[[step]]\nkind = \"inject\"\ninterface = \"lan\"\nframe = {{ kind = \"udp\", eth = {{ src = \"bad\", dst = \"02:00:00:00:00:01\" }}, {IP}, src-port = 1, dst-port = 2 }}\n"
    );
    let error = parse(&source).unwrap_err();
    assert_eq!(error.code(), Code::InvalidMacAddress);
    assert_eq!(
        error.path(),
        [
            PathSegment::Field("step"),
            PathSegment::Index(1),
            PathSegment::Field("frame"),
            PathSegment::Field("eth"),
            PathSegment::Field("src"),
        ]
    );
    assert_eq!(
        error.to_string(),
        "scenario rejected: InvalidMacAddress at step[1].frame.eth.src"
    );
    let unknown = parse(&format!("{HEAD}[[step]]\nkind = \"tick\"\nmystery = 1\n")).unwrap_err();
    assert_eq!(unknown.code(), Code::UnknownField);
    assert_eq!(
        unknown.path()[..2],
        [PathSegment::Field("step"), PathSegment::Index(0)]
    );
}

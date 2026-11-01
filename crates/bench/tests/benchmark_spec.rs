//! R17 benchmark specification v0.2 pin and consistency checks.
//!
//! The spec bytes must match the pinned `sha256sum`-format digest file, and
//! the tier/offered-load tables and every concrete case ID in the spec must be
//! consistent with the frozen hardware plan v1. This checks documentation
//! only; it measures nothing and asserts no performance value.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ruster_bench::{
    hardware_plan_v1, line_rate_packet_rate, AfxdpMode, HardwareFrame, HardwarePlanClass,
    PlannedHardwareCase,
};

const SPEC_PATH: &str = "docs/benchmark-spec-v0.2.md";
const DIGEST_PATH: &str = "docs/benchmark-spec-v0.2.sha256";
const TEN_GIGABIT: u64 = 10_000_000_000;

fn repo_file(relative: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn spec_text() -> String {
    String::from_utf8(repo_file(SPEC_PATH)).expect("spec is UTF-8")
}

/// Minimal FIPS 180-4 SHA-256 for test-only use (the workspace has no hash dependency).
fn sha256(message: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_length = u64::try_from(message.len())
        .expect("message length fits u64")
        .checked_mul(8)
        .expect("bit length fits u64");
    padded.extend_from_slice(&bit_length.to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut digest = [0_u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to String cannot fail");
        out
    })
}

#[test]
fn test_sha256_matches_fips_known_answers() {
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(
        hex(&sha256(&vec![b'a'; 1_000_000])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn benchmark_spec_v0_2_digest_matches_pinned_file() {
    let digest_file = String::from_utf8(repo_file(DIGEST_PATH)).expect("digest file is UTF-8");
    let expected_line = format!("{}  {SPEC_PATH}\n", hex(&sha256(&repo_file(SPEC_PATH))));
    assert_eq!(
        digest_file, expected_line,
        "{SPEC_PATH} changed without updating {DIGEST_PATH} \
         (regenerate with `sha256sum {SPEC_PATH} > {DIGEST_PATH}` and get owner approval)"
    );
}

#[test]
fn benchmark_spec_v0_2_is_marked_approved_by_owner() {
    let spec = spec_text();
    let status_lines: Vec<&str> = spec
        .lines()
        .filter(|line| line.starts_with("- status: "))
        .collect();
    assert_eq!(status_lines.len(), 1, "exactly one status line");
    assert_eq!(
        status_lines[0], "- status: **APPROVED — owner承認済み（#282）**",
        "v0.2 thresholds are frozen by the owner approval in #282"
    );
    assert!(
        !spec.contains("DRAFT") && !spec.contains("PROPOSED"),
        "an approved spec must not keep DRAFT/PROPOSED markers"
    );
    assert!(
        spec.lines()
            .any(|line| line.starts_with("- 承認: 2026-11-01、ownerが#282")),
        "the approval line must cite the 2026-11-01 owner decision"
    );
}

fn class_label(class: HardwarePlanClass) -> &'static str {
    match class {
        HardwarePlanClass::Primary => "primary",
        HardwarePlanClass::FlowOne => "flow-one",
        HardwarePlanClass::Flow64Imix => "flow64-imix",
        HardwarePlanClass::SingleQueue => "single-queue",
        HardwarePlanClass::CopyMode => "copy-mode",
        HardwarePlanClass::StandaloneFirewall => "standalone-firewall",
        HardwarePlanClass::UdpZero => "udp-zero",
        HardwarePlanClass::BatchSweep => "batch-sweep",
    }
}

/// The spec's ordered tier rule.
fn tier(case: &PlannedHardwareCase) -> &'static str {
    let fields = &case.case;
    if fields.mode == AfxdpMode::Copy || fields.batch_size != 64 {
        "R"
    } else if fields.queue_count == 1 || fields.flow_count == 1 {
        "SC"
    } else {
        "MQ"
    }
}

fn marked_table_rows(spec: &str, name: &str) -> Vec<Vec<String>> {
    let begin = format!("<!-- r17:{name}:begin -->");
    let end = format!("<!-- r17:{name}:end -->");
    let start = spec.find(&begin).expect("table begin marker") + begin.len();
    let stop = spec[start..].find(&end).expect("table end marker") + start;
    spec[start..stop]
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .skip(2) // header and separator
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect()
        })
        .collect()
}

#[test]
fn benchmark_spec_v0_2_matrix_matches_hardware_plan_v1() {
    let spec = spec_text();
    let plan = hardware_plan_v1().expect("frozen plan v1");

    // Tier table: exact (class, tier) -> count, recomputed from plan v1.
    let mut computed: BTreeMap<(String, String), usize> = BTreeMap::new();
    for case in &plan.cases {
        *computed
            .entry((class_label(case.class).to_owned(), tier(case).to_owned()))
            .or_default() += 1;
    }
    let mut documented: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in marked_table_rows(&spec, "tier-table") {
        assert_eq!(row.len(), 3, "tier row {row:?}");
        let count = row[2].parse().expect("tier count");
        assert!(
            documented
                .insert((row[0].clone(), row[1].clone()), count)
                .is_none(),
            "duplicate tier row {row:?}"
        );
    }
    assert_eq!(documented, computed);
    assert_eq!(documented.values().sum::<usize>(), 237);

    // Queue-count split cited in the hardware prerequisite and owner questions.
    let q1 = plan
        .cases
        .iter()
        .filter(|c| c.case.queue_count == 1)
        .count();
    let q4 = plan
        .cases
        .iter()
        .filter(|c| c.case.queue_count == 4)
        .count();
    assert_eq!((q1, q4), (36, 201));
    assert!(spec.contains("q1は36 case") && spec.contains("237中201 caseが`q4`"));

    // Offered table: floor(line rate * percent / 100) at 10 Gbit/s, and every
    // gated or report-only (tier, frame) pair in plan v1 has a load to use.
    let mut offered: BTreeMap<(String, String), u128> = BTreeMap::new();
    for row in marked_table_rows(&spec, "offered-table") {
        assert_eq!(row.len(), 4, "offered row {row:?}");
        let frame = [
            HardwareFrame::Eth64,
            HardwareFrame::Eth128,
            HardwareFrame::Eth512,
            HardwareFrame::Ipv4Mtu1500,
            HardwareFrame::RusterImixV1,
        ]
        .into_iter()
        .find(|frame| frame.label() == row[1])
        .unwrap_or_else(|| panic!("unknown frame in {row:?}"));
        let percent: u128 = row[2].parse().expect("percent");
        assert!((1..=100).contains(&percent), "percent in {row:?}");
        let rate = line_rate_packet_rate(frame, TEN_GIGABIT).expect("line rate");
        let expected = rate.numerator() * percent / (rate.denominator() * 100);
        let documented_pps: u128 = row[3].parse().expect("offered pps");
        assert_eq!(documented_pps, expected, "offered pps in {row:?}");
        assert!(
            offered
                .insert((row[0].clone(), row[1].clone()), documented_pps)
                .is_none(),
            "duplicate offered row {row:?}"
        );
    }
    for case in &plan.cases {
        let load_tier = match tier(case) {
            "R" => "MQ",
            other => other,
        };
        let key = (load_tier.to_owned(), case.case.frame.label().to_owned());
        assert!(
            offered.contains_key(&key),
            "no offered load for {}",
            case.case_id
        );
    }

    // Every concrete case ID cited in the spec exists in plan v1.
    let mut cited = 0;
    for token in spec.split('`').skip(1).step_by(2) {
        if token.starts_with("v1:") && !token.contains('{') {
            assert!(
                plan.cases.iter().any(|case| case.case_id == token),
                "spec cites unknown case ID {token}"
            );
            cited += 1;
        }
    }
    assert!(cited >= 2, "spec cites its soak and operator load cases");
}

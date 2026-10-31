//! R16 `config` and `scenario` targets: bounded document fuzzing.
//!
//! Each case is a structured random document (a valid router config or
//! scenario, or one with a typed perturbation) optionally followed by
//! byte-level mutations. A random secret-like token is planted in a value,
//! key, path, or seed position. The runner checks:
//!
//! - parsing/validation never panics, stays within the case time bound, and
//!   is deterministic (two runs give equal results);
//! - every rejection is value-free: neither the planted token nor a planted
//!   numeric seed (whole, any 8-byte fragment, or hex-encoded) appears in a
//!   config diagnostic/validation error's `Debug` or code (they implement no
//!   `Display`) or a scenario error's `Debug`, `Display`, or code, and an
//!   accepted unmutated document's `Debug` never shows a planted seed;
//! - documents the generator marks `MUST_ACCEPT` parse, validate, and (for
//!   configs) build a publication candidate.

use std::fmt::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use ruster_config::{parse, validate, ValidatedConfig, MAX_CONFIG_BYTES, MAX_INTERFACES};
use ruster_control::{PublicationSequencer, SimDeterministicKeySource};
use ruster_sim_scenario::{parse_scenario, MAX_SCENARIO_BYTES};

use super::envelope::{CaseEnvelope, Expected, InvariantFlags, Target, MAX_PAYLOAD_LEN};
use super::router::{RouterParams, LIMITS};
use super::targets::{CaseFailure, V1Rng};

/// Wall-clock bound for one document case (debug build, shared runner).
///
/// Checked only after the case returns: a case that never returns is cut
/// by the workflow's job timeout instead, which writes no replay artifact.
pub const MAX_DOCUMENT_CASE: Duration = Duration::from_secs(10);
/// Generated documents stay below this size; the 1 MiB / 256 KiB parser
/// input bounds are exercised by fixed tests.
pub const MAX_GENERATED_DOCUMENT: usize = 64 * 1024;
const MAX_SECRET: usize = 64;

/// Payload: `[secret_len][secret][numeric_len][numeric][document]`.
fn encode_payload(secret: &str, numeric: &str, document: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + secret.len() + numeric.len() + document.len());
    payload.push(u8::try_from(secret.len()).unwrap());
    payload.extend_from_slice(secret.as_bytes());
    payload.push(u8::try_from(numeric.len()).unwrap());
    payload.extend_from_slice(numeric.as_bytes());
    payload.extend_from_slice(document);
    payload
}

struct Document<'a> {
    secret: &'a str,
    numeric: &'a str,
    bytes: &'a [u8],
}

fn decode_payload(payload: &[u8]) -> Result<Document<'_>, CaseFailure> {
    fn text(bytes: &[u8]) -> Result<&str, CaseFailure> {
        std::str::from_utf8(bytes).map_err(|_| CaseFailure::new("planted token is not UTF-8"))
    }
    let secret_len = usize::from(
        *payload
            .first()
            .ok_or_else(|| CaseFailure::new("empty payload"))?,
    );
    if !(8..=MAX_SECRET).contains(&secret_len) || payload.len() < 2 + secret_len {
        return Err(CaseFailure::new("planted secret length is out of range"));
    }
    let secret = text(&payload[1..1 + secret_len])?;
    let numeric_at = 1 + secret_len;
    let numeric_len = usize::from(payload[numeric_at]);
    if !(8..=MAX_SECRET).contains(&numeric_len) || payload.len() < numeric_at + 1 + numeric_len {
        return Err(CaseFailure::new("planted numeric length is out of range"));
    }
    let numeric = text(&payload[numeric_at + 1..numeric_at + 1 + numeric_len])?;
    let bytes = &payload[numeric_at + 1 + numeric_len..];
    if bytes.len() > MAX_GENERATED_DOCUMENT {
        return Err(CaseFailure::new("generated document exceeds its bound"));
    }
    Ok(Document {
        secret,
        numeric,
        bytes,
    })
}

fn tokens(rng: &mut V1Rng) -> (String, String) {
    let secret = format!(
        "s3cr3tK3y{:016x}{:08x}",
        rng.next_u64(),
        rng.next_u64() as u32
    );
    // 19 digits, a canonical decimal u64 and a positive TOML integer.
    let numeric =
        (1_000_000_000_000_000_000 + rng.next_u64() % 8_000_000_000_000_000_000).to_string();
    (secret, numeric)
}

fn encode(
    target: Target,
    seed: u64,
    case_index: u64,
    must_accept: bool,
    secret: &str,
    numeric: &str,
    document: &[u8],
) -> Result<Vec<u8>, CaseFailure> {
    let payload = encode_payload(secret, numeric, document);
    debug_assert!(payload.len() <= MAX_PAYLOAD_LEN);
    let flags = if must_accept {
        InvariantFlags::MUST_ACCEPT
    } else {
        0
    };
    CaseEnvelope {
        target,
        seed,
        case_index,
        now: 0,
        ingress: 0,
        expected: Expected::Invariants(
            InvariantFlags::new(flags).map_err(|error| CaseFailure::new(format!("{error}")))?,
        ),
        payload: &payload,
    }
    .encode()
    .map_err(|error| CaseFailure::new(format!("encode {} case: {error}", target.name())))
}

/// Byte-level mutations that keep the document bounded.
fn mutate_bytes(document: &mut Vec<u8>, rng: &mut V1Rng) {
    for _ in 0..1 + rng.below(8) {
        if document.is_empty() {
            document.push(rng.byte());
            continue;
        }
        let at = rng.below(document.len());
        match rng.below(7) {
            0 => document[at] ^= 1 << rng.below(8),
            1 => document[at] = b"[]=\"'{},.\n#\\\0"[rng.below(13)],
            2 => {
                let end = (at + 1 + rng.below(32)).min(document.len());
                document.drain(at..end);
            }
            3 => {
                let end = (at + 1 + rng.below(64)).min(document.len());
                let copy = document[at..end].to_vec();
                if document.len() + copy.len() <= MAX_GENERATED_DOCUMENT {
                    let to = rng.below(document.len() + 1);
                    document.splice(to..to, copy);
                }
            }
            4 => document.truncate(at),
            5 => document.insert(at, rng.byte()),
            _ => {
                // Swap two lines' worth of bytes: reorder tables and keys.
                let other = rng.below(document.len());
                document.swap(at, other);
            }
        }
    }
}

/// Shortest planted fragment that counts as a leak.
pub const MIN_LEAK_FRAGMENT: usize = 8;

/// Index of the first planted token that leaks into `haystack`, whole, as
/// any [`MIN_LEAK_FRAGMENT`]-byte fragment, or hex-encoded (as raw frame
/// bytes would render). Tokens are ASCII alphanumeric, so `Debug` string
/// escaping leaves them unchanged.
pub fn leaked(haystack: &str, needles: &[&str]) -> Option<usize> {
    needles.iter().position(|needle| {
        let hex: String = needle.bytes().map(|byte| format!("{byte:02x}")).collect();
        haystack.contains(hex.as_str())
            || needle
                .as_bytes()
                .windows(MIN_LEAK_FRAGMENT.min(needle.len()))
                .any(|fragment| {
                    haystack.contains(std::str::from_utf8(fragment).expect("ASCII token"))
                })
    })
}

fn timed<T>(label: &str, run: impl FnOnce() -> T) -> Result<T, CaseFailure> {
    let started = Instant::now();
    let value = run();
    let elapsed = started.elapsed();
    if elapsed > MAX_DOCUMENT_CASE {
        return Err(CaseFailure::new(format!(
            "{label} took {elapsed:?}, above the {MAX_DOCUMENT_CASE:?} case bound"
        )));
    }
    Ok(value)
}

// --- config -----------------------------------------------------------------

fn random_router(rng: &mut V1Rng) -> RouterParams {
    let small = |rng: &mut V1Rng| 1 + u32::try_from(rng.below(64)).unwrap();
    RouterParams {
        udp_mappings: small(rng),
        udp_peers: small(rng),
        tcp_mappings: small(rng),
        tcp_sessions: small(rng),
        firewall_states: 4 + small(rng),
        ports: 1 + u16::try_from(rng.below(512)).unwrap(),
        alternate_route: rng.below(2) == 0,
        deny_dns: rng.below(2) == 0,
        resolution_interval_ms: 1_000 + u64::try_from(rng.below(2_001)).unwrap(),
        icmpv4_interval_ms: 1 + u64::try_from(rng.below(1_000)).unwrap(),
        wan_mac_last: 2 + u8::try_from(rng.below(200)).unwrap(),
        include_nat: true,
        offlink_route: false,
    }
}

fn replace_once(document: &mut String, from: &str, to: &str) {
    if let Some(at) = document.find(from) {
        document.replace_range(at..at + from.len(), to);
    }
}

pub fn generate_config(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::Config, seed, case_index);
    let (secret, numeric) = tokens(&mut rng);
    let params = random_router(&mut rng);
    let mut document = params.render();
    // The UDP allocator seed is always the planted numeric seed.
    replace_once(
        &mut document,
        "allocator-seed = \"11\"",
        &format!("allocator-seed = \"{numeric}\""),
    );
    let mode = rng.below(18);
    let mut must_accept = false;
    match mode {
        0..=3 => must_accept = true,
        4 => document.insert_str(document.find('\n').unwrap() + 1, &format!("{secret} = 1\n")),
        5 => replace_once(
            &mut document,
            "allocator-seed = \"12\"",
            &format!("allocator-seed = \"{secret}\""),
        ),
        6 => replace_once(
            &mut document,
            "name = \"lan\"",
            &format!("name = \"{secret}\""),
        ),
        7 => replace_once(
            &mut document,
            "name = \"wan\"",
            &format!("name = \"wan\\n{secret}\""),
        ),
        8 => replace_once(
            &mut document,
            "default-ttl = 64",
            &format!("default-ttl = \"{secret}\""),
        ),
        9 => replace_once(
            &mut document,
            "[nat44.udp]\n",
            &format!("[nat44.udp]\nhash-key = \"{secret}\"\n"),
        ),
        10 => document.push_str("rx = 32\n"),
        11 => {
            let _ = write!(
                document,
                "\n[[routes]]\nprefix = \"10.1.0.0/16\"\negress = \"wan\"\nvia = \"10.2.0.1\"\n# {secret}\n"
            );
        }
        12 => {
            // One interface more than the V1 list bound.
            for index in 0..=MAX_INTERFACES {
                let _ = write!(
                    document,
                    "\n[[interfaces]]\nid = {}\nname = \"x{index}\"\ndevice = \"d{index}\"\nmac = \"02:00:00:01:{:02x}:{:02x}\"\n",
                    100 + index,
                    index >> 8,
                    index & 0xff
                );
            }
        }
        13 => replace_once(
            &mut document,
            "schema-version = 1",
            [
                "schema-version = 2",
                "schema-version = \"1\"",
                "",
                "schema-version = 1.0",
            ][rng.below(4)],
        ),
        14 => replace_once(&mut document, "states = 8\n", "states = 4294967295\n"),
        15 => replace_once(
            &mut document,
            "mac = \"02:00:00:00:00:01\"",
            &format!("mac = \"{secret}\""),
        ),
        16 => replace_once(
            &mut document,
            "device = \"sim1\"",
            &format!("device = \"--{secret}\""),
        ),
        _ => {
            if rng.below(2) == 0 {
                replace_once(
                    &mut document,
                    "allocator-seed = \"12\"",
                    &format!("allocator-seed = \"{secret}\""),
                );
            } else {
                document.insert_str(0, &format!("# {secret}\n"));
            }
        }
    }
    let mut bytes = document.into_bytes();
    if !must_accept && rng.below(3) == 0 {
        mutate_bytes(&mut bytes, &mut rng);
    }
    bytes.truncate(MAX_GENERATED_DOCUMENT);
    encode(
        Target::Config,
        seed,
        case_index,
        must_accept,
        &secret,
        &numeric,
        &bytes,
    )
}

/// Which stage, if any, rejected one document case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentOutcome {
    Accepted,
    ParseRejected,
    ValidationRejected,
    BridgeRejected,
}

pub fn run_config(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    run_config_outcome(case).map(|_| ())
}

pub fn run_config_outcome(case: &CaseEnvelope<'_>) -> Result<DocumentOutcome, CaseFailure> {
    let Expected::Invariants(flags) = case.expected else {
        return Err(CaseFailure::new(
            "config target has a non-invariant expected value",
        ));
    };
    let document = decode_payload(case.payload)?;
    let planted = [document.secret, document.numeric];
    let leak = |label: &str, rendered: &str| -> Result<(), CaseFailure> {
        match leaked(rendered, &planted) {
            Some(which) => Err(CaseFailure::new(format!(
                "{label} echoes planted {}",
                ["secret token", "numeric seed"][which]
            ))),
            None => Ok(()),
        }
    };
    timed(
        "config parse/validate",
        || -> Result<DocumentOutcome, CaseFailure> {
            let first = parse(document.bytes);
            let second = parse(document.bytes);
            if first != second {
                return Err(CaseFailure::new("config parse is not deterministic"));
            }
            let parsed = match first {
                Err(diagnostic) => {
                    leak("parse diagnostic Debug", &format!("{diagnostic:?}"))?;
                    leak("parse diagnostic code", diagnostic.code().code())?;
                    if flags.must_accept() {
                        return Err(CaseFailure::new(format!(
                            "valid config rejected by parse: {:?}",
                            diagnostic.code()
                        )));
                    }
                    return Ok(DocumentOutcome::ParseRejected);
                }
                Ok(parsed) => parsed,
            };
            if flags.must_accept() {
                // A mutated document may legitimately carry either token in an
                // accepted value; the unmutated document only plants the seed.
                leak("accepted config Debug", &format!("{parsed:?}"))?;
            }
            let again = validate(parsed.clone(), LIMITS);
            let validated = validate(parsed, LIMITS);
            let config = match (validated, again) {
                (Err(error), Err(repeat)) => {
                    if error != repeat {
                        return Err(CaseFailure::new("config validation is not deterministic"));
                    }
                    leak("validation error Debug", &format!("{error:?}"))?;
                    leak("validation error code", error.code().code())?;
                    if flags.must_accept() {
                        return Err(CaseFailure::new(format!(
                            "valid config rejected by validation: {:?}",
                            error.code()
                        )));
                    }
                    return Ok(DocumentOutcome::ValidationRejected);
                }
                (Ok(ValidatedConfig::V1(config)), Ok(_)) => config,
                (Ok(_), Ok(_)) => return Err(CaseFailure::new("unknown validated config version")),
                _ => return Err(CaseFailure::new("config validation is not deterministic")),
            };
            let mut sequencer =
                PublicationSequencer::new(SimDeterministicKeySource::new(case.seed));
            let outcome = match sequencer.candidate(&config) {
                Ok(_) => DocumentOutcome::Accepted,
                Err(error) => {
                    leak("candidate error Debug", &format!("{error:?}"))?;
                    if flags.must_accept() {
                        return Err(CaseFailure::new(format!(
                            "valid config rejected by the bridge: {error:?}"
                        )));
                    }
                    DocumentOutcome::BridgeRejected
                }
            };
            if flags.must_accept() {
                leak("sequencer Debug", &format!("{sequencer:?}"))?;
            }
            Ok(outcome)
        },
    )?
}

/// Inputs just above each document bound are rejected before any parsing,
/// with only the numeric limit and length in the diagnostic.
pub fn check_document_input_bounds() -> Result<(), CaseFailure> {
    let secret = "s3cr3tK3yBoundary0123456789";
    let mut oversized = format!("schema-version = 1\n# {secret}\n").into_bytes();
    oversized.resize(MAX_CONFIG_BYTES + 1, b'#');
    let diagnostic = parse(&oversized)
        .err()
        .ok_or_else(|| CaseFailure::new("oversized config accepted"))?;
    if diagnostic.code() != ruster_config::DiagnosticCode::InputTooLarge
        || diagnostic.limit() != Some(MAX_CONFIG_BYTES)
        || diagnostic.actual() != Some(MAX_CONFIG_BYTES + 1)
        || leaked(&format!("{diagnostic:?}"), &[secret]).is_some()
    {
        return Err(CaseFailure::new(
            "oversized config diagnostic is not bounded/value-free",
        ));
    }
    let mut oversized = format!("schema = \"ruster-scenario/v1\"\n# {secret}\n").into_bytes();
    oversized.resize(MAX_SCENARIO_BYTES + 1, b'#');
    let error = parse_scenario(&oversized, Path::new("/r16"))
        .err()
        .ok_or_else(|| CaseFailure::new("oversized scenario accepted"))?;
    if error.code() != ruster_sim_scenario::ScenarioErrorCode::InputTooLarge
        || error.limit() != Some(MAX_SCENARIO_BYTES as u64)
        || leaked(&format!("{error:?}{error}"), &[secret]).is_some()
    {
        return Err(CaseFailure::new(
            "oversized scenario error is not bounded/value-free",
        ));
    }
    Ok(())
}

// --- scenario ---------------------------------------------------------------

const SCENARIO_BASE: &str = "/r16/scenario";

fn udp_frame(rng: &mut V1Rng) -> String {
    format!(
        "{{ kind = \"udp\", eth = {{ src = \"02:00:00:00:00:10\", dst = \"02:00:00:00:00:01\" }}, \
         ip = {{ src = \"192.168.1.10\", dst = \"198.51.100.{}\", id = {}, ttl = {} }}, \
         src-port = {}, dst-port = {}, payload-ascii = \"q{}\" }}",
        1 + rng.below(250),
        rng.below(65_536),
        1 + rng.below(255),
        1 + rng.below(65_535),
        1 + rng.below(65_535),
        rng.below(1_000)
    )
}

fn scenario_frame(rng: &mut V1Rng) -> String {
    match rng.below(4) {
        0 => udp_frame(rng),
        1 => format!(
            "{{ kind = \"tcp\", eth = {{ src = \"02:00:00:00:00:10\", dst = \"02:00:00:00:00:01\" }}, \
             ip = {{ src = \"192.168.1.10\", dst = \"198.51.100.20\", id = {} }}, src-port = {}, \
             dst-port = 80, seq = {}, flags = [\"syn\"], window = 4096 }}",
            rng.below(65_536),
            1 + rng.below(65_535),
            rng.next_u64() as u32
        ),
        2 => "{ kind = \"arp\", eth = { src = \"02:00:00:00:00:fe\", dst = \"02:00:00:00:00:02\" }, \
              op = \"reply\", sender-mac = \"02:00:00:00:00:fe\", sender-ip = \"203.0.113.1\", \
              target-mac = \"02:00:00:00:00:02\", target-ip = \"203.0.113.2\", pad-to-min = true }"
            .to_owned(),
        _ => {
            let mut hex = String::new();
            for _ in 0..14 + rng.below(50) {
                let _ = write!(hex, "{:02x} ", rng.byte());
            }
            format!("{{ kind = \"raw\", hex = \"{}\" }}", hex.trim_end())
        }
    }
}

pub fn generate_scenario(seed: u64, case_index: u64) -> Result<Vec<u8>, CaseFailure> {
    let mut rng = V1Rng::for_case(Target::Scenario, seed, case_index);
    let (secret, numeric) = tokens(&mut rng);
    let config = ["router.toml", "m1/router-v1.toml", "./a/./b.toml"][rng.below(3)];
    let mut document = format!(
        "schema = \"ruster-scenario/v1\"\nseed = {numeric}\nconfig = \"{config}\"\nstart-ms = {}\n",
        rng.below(10_000)
    );
    let mut now = 10_000_u64;
    let steps = 1 + rng.below(24);
    for _ in 0..steps {
        let step = match rng.below(5) {
            0 | 1 => format!(
                "kind = \"inject\"\ninterface = \"{}\"\nframe = {}\n",
                ["lan", "wan"][rng.below(2)],
                scenario_frame(&mut rng)
            ),
            2 => {
                now += u64::try_from(rng.below(5_000)).unwrap();
                if rng.below(2) == 0 {
                    format!("kind = \"tick\"\nat-ms = {now}\nticks = {}\n", 1 + rng.below(8))
                } else {
                    format!("kind = \"tick\"\nadvance-ms = {}\n", rng.below(1_000))
                }
            }
            3 => format!(
                "kind = \"apply\"\nconfig = \"router-v{}.toml\"\noutcome = \"{}\"\n",
                rng.below(3),
                ["applied", "rejected"][rng.below(2)]
            ),
            _ => format!(
                "kind = \"expect\"\ngeneration = {}\ntx = [ {{ interface = \"wan\", frame = {} }} ]\n\
                 drops = [{{ reason = \"NEIGHBOR_UNRESOLVED\", count = {} }}]\n",
                1 + rng.below(4),
                udp_frame(&mut rng),
                rng.below(4)
            ),
        };
        let _ = write!(document, "\n[[step]]\n{step}");
    }
    if rng.below(4) == 0 {
        document.push_str("\n[[step]]\nkind = \"hold\"\n");
    }
    let mode = rng.below(14);
    let mut must_accept = false;
    match mode {
        0..=4 => must_accept = true,
        5 => replace_once(&mut document, "config = ", &format!("config = \"../{secret}\"\n#")),
        6 => replace_once(&mut document, "config = ", &format!("config = \"/{secret}/r.toml\"\n#")),
        7 => document.push_str(&format!("\n[[step]]\nkind = \"inject\"\ninterface = \"lan {secret}\"\nframe = {{ kind = \"raw\", hex = \"00\" }}\n")),
        8 => document.push_str(&format!("\n[[step]]\nkind = \"inject\"\ninterface = \"lan\"\nframe = {{ kind = \"raw\", hex = \"zz{secret}\" }}\n")),
        9 => document.push_str(&format!("\n[[step]]\nkind = \"expect\"\ndrops = [{{ reason = \"{secret}\", count = 1 }}]\n")),
        10 => document.push_str(&format!("\n[[step]]\nkind = \"{secret}\"\n")),
        11 => document.insert_str(0, &format!("{secret} = 1\n")),
        12 => replace_once(
            &mut document,
            "schema = \"ruster-scenario/v1\"",
            &format!("schema = \"{secret}\""),
        ),
        _ => document.push_str(&format!("\n[[step]]\nkind = \"tick\"\nat-ms = 0\n# {secret}\n")),
    }
    let mut bytes = document.into_bytes();
    if !must_accept && rng.below(3) == 0 {
        mutate_bytes(&mut bytes, &mut rng);
    }
    bytes.truncate(MAX_GENERATED_DOCUMENT);
    encode(
        Target::Scenario,
        seed,
        case_index,
        must_accept,
        &secret,
        &numeric,
        &bytes,
    )
}

pub fn run_scenario(case: &CaseEnvelope<'_>) -> Result<(), CaseFailure> {
    run_scenario_outcome(case).map(|_| ())
}

pub fn run_scenario_outcome(case: &CaseEnvelope<'_>) -> Result<DocumentOutcome, CaseFailure> {
    let Expected::Invariants(flags) = case.expected else {
        return Err(CaseFailure::new(
            "scenario target has a non-invariant expected value",
        ));
    };
    let document = decode_payload(case.payload)?;
    let planted = [document.secret, document.numeric];
    timed(
        "scenario parse",
        || -> Result<DocumentOutcome, CaseFailure> {
            let base = Path::new(SCENARIO_BASE);
            let first = parse_scenario(document.bytes, base);
            if first != parse_scenario(document.bytes, base) {
                return Err(CaseFailure::new("scenario parse is not deterministic"));
            }
            let rendered = match &first {
                // A mutated document may legitimately carry either token in an
                // accepted value; the unmutated document only plants the seed.
                Ok(scenario) if flags.must_accept() => format!("{scenario:?}"),
                Ok(_) => String::new(),
                Err(error) => format!("{error:?} {error} {:?}", error.code()),
            };
            if let Some(which) = leaked(&rendered, &planted) {
                return Err(CaseFailure::new(format!(
                    "scenario {} echoes planted {}",
                    if first.is_ok() { "Debug" } else { "error" },
                    ["secret token", "numeric seed"][which]
                )));
            }
            match first {
                Err(error) if flags.must_accept() => Err(CaseFailure::new(format!(
                    "valid scenario rejected: {error}"
                ))),
                Ok(scenario)
                    if flags.must_accept()
                        && scenario.seed.get().to_string() != document.numeric =>
                {
                    Err(CaseFailure::new("accepted scenario lost its seed"))
                }
                Ok(_) => Ok(DocumentOutcome::Accepted),
                Err(_) => Ok(DocumentOutcome::ParseRejected),
            }
        },
    )?
}

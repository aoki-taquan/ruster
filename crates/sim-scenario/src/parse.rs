use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};

use ruster_core::{ConsumeReason, DropReason, MacAddress};
use serde::de::DeserializeOwned;
use serde::de::IntoDeserializer;
use serde::Deserialize;
use serde_path_to_error::Segment;
use toml::Value;

use crate::error::{PathSegment, ScenarioError, ScenarioErrorCode as Code};
use crate::frame::{
    ArpOperation, ArpSpec, EthernetSpec, FrameBuildError, FrameSpec, IcmpEchoKind, Ipv4Spec,
    TcpFlags,
};
use crate::model::{
    ApplyOutcome, Expectation, ExpectedTx, InterfaceName, RejectReason, Scenario, ScenarioPath,
    ScenarioSeed, Step,
};
use crate::Frame;

/// The only accepted value of the top-level `schema` field.
pub const SCENARIO_SCHEMA_V1: &str = "ruster-scenario/v1";
pub const MAX_SCENARIO_BYTES: usize = 256 * 1024;
pub const MAX_STEPS: usize = 4096;
pub const MAX_EXPECTED_TX: usize = 1024;
pub const MAX_TICKS_PER_STEP: u32 = 65_536;
pub const MAX_TOTAL_TICKS: u64 = 1 << 20;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_INTERFACE_NAME_BYTES: usize = 64;

/// Schema field names. Only these ever appear in an error path.
#[rustfmt::skip]
const FIELDS: &[&str] = &[
    "ack", "advance-ms", "at-ms", "config", "consumes", "count", "df", "drops", "dst",
    "dst-port", "eth", "ether-type", "flags", "fragment-offset", "frame", "generation", "hex",
    "id", "interface", "ip", "kind", "mf", "op", "outcome", "pad-to-min", "payload-ascii",
    "payload-hex",
    "protocol", "reason", "reserved", "schema", "seed", "sender-ip", "sender-mac", "seq", "src",
    "src-port", "start-ms", "step", "target-ip", "target-mac", "ticks", "tos", "ttl", "tx",
    "window", "zero-checksum",
];

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ScenarioDto {
    #[allow(dead_code)]
    schema: String,
    seed: u64,
    #[serde(default)]
    start_ms: u64,
    config: String,
    #[serde(default)]
    step: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct InjectDto {
    interface: String,
    frame: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct TickDto {
    advance_ms: Option<u64>,
    at_ms: Option<u64>,
    ticks: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ApplyDto {
    config: String,
    outcome: OutcomeDto,
    reason: Option<RejectReasonDto>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RejectReasonDto {
    RestartRequired,
    Invalid,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OutcomeDto {
    Applied,
    Rejected,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ExpectDto {
    tx: Option<Vec<TxDto>>,
    #[serde(default)]
    drops: Vec<CountDto>,
    #[serde(default)]
    consumes: Vec<CountDto>,
    generation: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct HoldDto {}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct TxDto {
    interface: String,
    frame: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct CountDto {
    reason: String,
    count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawDto {
    hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct EthDto {
    src: String,
    dst: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct IpDto {
    src: String,
    dst: String,
    ttl: Option<u8>,
    id: Option<u16>,
    tos: Option<u8>,
    df: Option<bool>,
    mf: Option<bool>,
    reserved: Option<bool>,
    fragment_offset: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct EthernetFrameDto {
    eth: EthDto,
    #[serde(default)]
    pad_to_min: bool,
    ether_type: u16,
    payload_hex: Option<String>,
    payload_ascii: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OpDto {
    Request,
    Reply,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ArpDto {
    eth: EthDto,
    #[serde(default)]
    pad_to_min: bool,
    op: OpDto,
    sender_mac: String,
    sender_ip: String,
    target_mac: Option<String>,
    target_ip: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Ipv4FrameDto {
    eth: EthDto,
    #[serde(default)]
    pad_to_min: bool,
    ip: IpDto,
    protocol: u8,
    payload_hex: Option<String>,
    payload_ascii: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct IcmpEchoDto {
    eth: EthDto,
    #[serde(default)]
    pad_to_min: bool,
    ip: IpDto,
    op: OpDto,
    #[serde(default)]
    id: u16,
    #[serde(default)]
    seq: u16,
    payload_hex: Option<String>,
    payload_ascii: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct UdpDto {
    eth: EthDto,
    #[serde(default)]
    pad_to_min: bool,
    ip: IpDto,
    src_port: u16,
    dst_port: u16,
    #[serde(default)]
    zero_checksum: bool,
    payload_hex: Option<String>,
    payload_ascii: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TcpFlagDto {
    Fin,
    Syn,
    Rst,
    Psh,
    Ack,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct TcpDto {
    eth: EthDto,
    #[serde(default)]
    pad_to_min: bool,
    ip: IpDto,
    src_port: u16,
    dst_port: u16,
    #[serde(default)]
    seq: u32,
    #[serde(default)]
    ack: u32,
    #[serde(default)]
    flags: Vec<TcpFlagDto>,
    window: Option<u16>,
    payload_hex: Option<String>,
    payload_ascii: Option<String>,
}

/// Parses a bounded `ruster-scenario/v1` TOML document.
///
/// Relative configuration paths are resolved against `base_dir`, normally the
/// directory containing the scenario file. No file is opened.
///
/// # Errors
///
/// Returns a value-free [`ScenarioError`] for oversized or malformed input,
/// unknown or duplicate fields, unsupported schemas, out-of-bound lists,
/// unconfined paths, invalid addresses or payloads, non-monotonic time, and
/// misplaced hold markers.
pub fn parse_scenario(input: &[u8], base_dir: &Path) -> Result<Scenario, ScenarioError> {
    if input.len() > MAX_SCENARIO_BYTES {
        return Err(ScenarioError::bounded(
            Code::InputTooLarge,
            &[],
            MAX_SCENARIO_BYTES as u64,
            input.len() as u64,
        ));
    }
    let source =
        std::str::from_utf8(input).map_err(|_| ScenarioError::new(Code::InvalidUtf8, &[]))?;
    let value = toml::from_str::<Value>(source).map_err(|error| {
        let message = error.message();
        let code = if message.contains("duplicate key") || message.contains("duplicate field") {
            Code::DuplicateField
        } else {
            Code::InvalidToml
        };
        ScenarioError::new(code, &[])
    })?;
    let table = value
        .as_table()
        .ok_or_else(|| ScenarioError::new(Code::InvalidType, &[]))?;
    let schema_path = [PathSegment::Field("schema")];
    match table.get("schema") {
        None => return Err(ScenarioError::new(Code::MissingSchema, &schema_path)),
        Some(Value::String(schema)) if schema == SCENARIO_SCHEMA_V1 => {}
        Some(_) => return Err(ScenarioError::new(Code::UnsupportedSchema, &schema_path)),
    }
    if let Some(Value::Array(steps)) = table.get("step") {
        check_list(&[PathSegment::Field("step")], steps.len(), MAX_STEPS)?;
    }
    let dto: ScenarioDto = decode(value, &[])?;
    convert(dto, base_dir)
}

/// Decodes one exact DTO and prefixes the value-free serde path.
///
/// Unknown/duplicate/missing classification relies on serde and toml error
/// message text; re-check `every_rejection_class_is_typed` on upgrades.
fn decode<T: DeserializeOwned>(value: Value, prefix: &[PathSegment]) -> Result<T, ScenarioError> {
    serde_path_to_error::deserialize(value.into_deserializer()).map_err(|error| {
        let message = error.inner().message();
        let code = if message.contains("unknown field") {
            Code::UnknownField
        } else if message.contains("duplicate field") {
            Code::DuplicateField
        } else if message.contains("missing field") {
            Code::MissingField
        } else if message.contains("unknown variant") {
            Code::UnknownKind
        } else {
            Code::InvalidType
        };
        let mut path = prefix.to_vec();
        path.extend(error.path().iter().filter_map(|segment| {
            match segment {
                Segment::Seq { index } => Some(PathSegment::Index(*index)),
                Segment::Map { key } => FIELDS
                    .iter()
                    .find(|field| **field == key.as_str())
                    .map(|field| PathSegment::Field(field)),
                Segment::Enum { .. } | Segment::Unknown => None,
            }
        }));
        ScenarioError::new(code, &path)
    })
}

/// Splits the `kind` discriminator from a table so the variant DTO can be
/// decoded with full error paths.
fn split_kind(value: Value, at: &Cursor) -> Result<(String, Value), ScenarioError> {
    let Value::Table(mut table) = value else {
        return Err(ScenarioError::new(Code::InvalidType, &at.0));
    };
    match table.remove("kind") {
        Some(Value::String(kind)) => Ok((kind, Value::Table(table))),
        Some(_) => Err(at.error("kind", Code::InvalidType)),
        None => Err(at.error("kind", Code::MissingField)),
    }
}

fn check_list(path: &[PathSegment], actual: usize, limit: usize) -> Result<(), ScenarioError> {
    if actual > limit {
        Err(ScenarioError::bounded(
            Code::ListTooLong,
            path,
            limit as u64,
            actual as u64,
        ))
    } else {
        Ok(())
    }
}

/// A growable value-free path used during semantic conversion.
struct Cursor(Vec<PathSegment>);

impl Cursor {
    fn at(&self, field: &'static str) -> Vec<PathSegment> {
        let mut path = self.0.clone();
        path.push(PathSegment::Field(field));
        path
    }

    fn child(&self, field: &'static str) -> Self {
        Self(self.at(field))
    }

    fn index(&self, field: &'static str, index: usize) -> Self {
        let mut path = self.at(field);
        path.push(PathSegment::Index(index));
        Self(path)
    }

    fn error(&self, field: &'static str, code: Code) -> ScenarioError {
        ScenarioError::new(code, &self.at(field))
    }
}

fn convert(dto: ScenarioDto, base_dir: &Path) -> Result<Scenario, ScenarioError> {
    let root = Cursor(Vec::new());
    let config = confined_path(&dto.config, base_dir, &root.at("config"))?;
    let mut now = dto.start_ms;
    let mut total_ticks = 0_u64;
    let count = dto.step.len();
    let mut steps = Vec::with_capacity(count);
    for (index, step) in dto.step.into_iter().enumerate() {
        let at = root.index("step", index);
        let (kind, body) = split_kind(step, &at)?;
        steps.push(match kind.as_str() {
            "inject" => {
                let inject: InjectDto = decode(body, &at.0)?;
                Step::Inject {
                    interface: interface_name(&inject.interface, &at.at("interface"))?,
                    frame: frame(inject.frame, &at.child("frame"))?,
                }
            }
            "tick" => {
                let tick: TickDto = decode(body, &at.0)?;
                now = match (tick.advance_ms, tick.at_ms) {
                    (Some(_), Some(_)) => return Err(at.error("at-ms", Code::ConflictingTime)),
                    (Some(advance), None) => now
                        .checked_add(advance)
                        .ok_or_else(|| at.error("advance-ms", Code::TimeOverflow))?,
                    (None, Some(target)) if target < now => {
                        return Err(at.error("at-ms", Code::TimeRegression))
                    }
                    (None, Some(target)) => target,
                    (None, None) => now,
                };
                let ticks = tick.ticks.unwrap_or(1);
                if ticks == 0 || ticks > MAX_TICKS_PER_STEP {
                    return Err(ScenarioError::bounded(
                        Code::TickCountOutOfRange,
                        &at.at("ticks"),
                        u64::from(MAX_TICKS_PER_STEP),
                        u64::from(ticks),
                    ));
                }
                total_ticks += u64::from(ticks);
                if total_ticks > MAX_TOTAL_TICKS {
                    return Err(ScenarioError::bounded(
                        Code::TooManyTicks,
                        &at.at("ticks"),
                        MAX_TOTAL_TICKS,
                        total_ticks,
                    ));
                }
                Step::Tick { at_ms: now, ticks }
            }
            "apply" => {
                let apply: ApplyDto = decode(body, &at.0)?;
                let reason = apply.reason.map(|reason| match reason {
                    RejectReasonDto::RestartRequired => RejectReason::RestartRequired,
                    RejectReasonDto::Invalid => RejectReason::Invalid,
                });
                Step::Apply {
                    config: confined_path(&apply.config, base_dir, &at.at("config"))?,
                    outcome: match (apply.outcome, reason) {
                        (OutcomeDto::Applied, None) => ApplyOutcome::Applied,
                        (OutcomeDto::Applied, Some(_)) => {
                            return Err(at.error("reason", Code::ReasonWithoutRejection))
                        }
                        (OutcomeDto::Rejected, reason) => ApplyOutcome::Rejected { reason },
                    },
                }
            }
            "expect" => Step::Expect(expectation(decode(body, &at.0)?, &at)?),
            "hold" => {
                let HoldDto {} = decode(body, &at.0)?;
                if index + 1 != count {
                    return Err(at.error("kind", Code::HoldNotLast));
                }
                Step::Hold
            }
            _ => return Err(at.error("kind", Code::UnknownKind)),
        });
    }
    Ok(Scenario {
        seed: ScenarioSeed::new(dto.seed),
        start_ms: dto.start_ms,
        config,
        steps,
    })
}

fn expectation(dto: ExpectDto, at: &Cursor) -> Result<Expectation, ScenarioError> {
    if dto.tx.is_none()
        && dto.drops.is_empty()
        && dto.consumes.is_empty()
        && dto.generation.is_none()
    {
        return Err(at.error("kind", Code::EmptyExpectation));
    }
    let tx = match dto.tx {
        None => None,
        Some(list) => {
            check_list(&at.at("tx"), list.len(), MAX_EXPECTED_TX)?;
            let mut out = Vec::with_capacity(list.len());
            for (index, entry) in list.into_iter().enumerate() {
                let entry_at = at.index("tx", index);
                out.push(ExpectedTx {
                    interface: interface_name(&entry.interface, &entry_at.at("interface"))?,
                    frame: frame(entry.frame, &entry_at.child("frame"))?,
                });
            }
            Some(out)
        }
    };
    let drops = reason_counts(dto.drops, &at.child("drops"), &DropReason::ALL, |r| {
        r.code()
    })?;
    let consumes = reason_counts(
        dto.consumes,
        &at.child("consumes"),
        &ConsumeReason::ALL,
        |r| r.code(),
    )?;
    let generation = match dto.generation {
        None => None,
        Some(value) => Some(
            NonZeroU64::new(value).ok_or_else(|| at.error("generation", Code::ZeroGeneration))?,
        ),
    };
    Ok(Expectation {
        tx,
        drops,
        consumes,
        generation,
    })
}

fn reason_counts<R: Copy + Eq>(
    list: Vec<CountDto>,
    at: &Cursor,
    all: &[R],
    code: impl Fn(R) -> &'static str,
) -> Result<Vec<(R, u64)>, ScenarioError> {
    let mut out: Vec<(R, u64)> = Vec::with_capacity(list.len());
    for (index, entry) in list.into_iter().enumerate() {
        let path = {
            let mut path = at.0.clone();
            path.push(PathSegment::Index(index));
            Cursor(path)
        };
        let reason = all
            .iter()
            .copied()
            .find(|reason| code(*reason) == entry.reason)
            .ok_or_else(|| path.error("reason", Code::UnknownReason))?;
        if out.iter().any(|(seen, _)| *seen == reason) {
            return Err(path.error("reason", Code::DuplicateReason));
        }
        out.push((reason, entry.count));
    }
    Ok(out)
}

fn confined_path(
    value: &str,
    base_dir: &Path,
    path: &[PathSegment],
) -> Result<ScenarioPath, ScenarioError> {
    if value.len() > MAX_PATH_BYTES {
        return Err(ScenarioError::bounded(
            Code::PathTooLong,
            path,
            MAX_PATH_BYTES as u64,
            value.len() as u64,
        ));
    }
    // `\` and `:` are rejected for portability and to keep operator intent
    // unambiguous (no Windows separators, drive prefixes, or URL-like forms).
    if value.contains(['\0', '\\', ':']) {
        return Err(ScenarioError::new(Code::InvalidPath, path));
    }
    let mut relative = PathBuf::new();
    for component in Path::new(value).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            Component::ParentDir => return Err(ScenarioError::new(Code::PathEscapesBase, path)),
            Component::RootDir | Component::Prefix(_) => {
                return Err(ScenarioError::new(Code::AbsolutePath, path))
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(ScenarioError::new(Code::InvalidPath, path));
    }
    Ok(ScenarioPath::new(relative, base_dir))
}

fn interface_name(value: &str, path: &[PathSegment]) -> Result<InterfaceName, ScenarioError> {
    if value.is_empty()
        || value.len() > MAX_INTERFACE_NAME_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ScenarioError::new(Code::InvalidInterfaceName, path));
    }
    Ok(InterfaceName(value.to_owned()))
}

fn mac(value: &str, path: &[PathSegment]) -> Result<MacAddress, ScenarioError> {
    let mut octets = [0_u8; 6];
    let mut parts = value.split(':');
    for octet in &mut octets {
        let part = parts.next().unwrap_or_default();
        if part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ScenarioError::new(Code::InvalidMacAddress, path));
        }
        *octet = u8::from_str_radix(part, 16)
            .map_err(|_| ScenarioError::new(Code::InvalidMacAddress, path))?;
    }
    if parts.next().is_some() {
        return Err(ScenarioError::new(Code::InvalidMacAddress, path));
    }
    Ok(MacAddress(octets))
}

fn ipv4(value: &str, path: &[PathSegment]) -> Result<Ipv4Addr, ScenarioError> {
    value
        .parse()
        .map_err(|_| ScenarioError::new(Code::InvalidIpv4Address, path))
}

fn hex(value: &str, path: &[PathSegment]) -> Result<Vec<u8>, ScenarioError> {
    // ASCII whitespace is allowed only between complete octets.
    let mut digits = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        if !byte.is_ascii_whitespace() {
            digits.push(byte);
        } else if !digits.len().is_multiple_of(2) {
            return Err(ScenarioError::new(Code::InvalidHex, path));
        }
    }
    if !digits.len().is_multiple_of(2) {
        return Err(ScenarioError::new(Code::InvalidHex, path));
    }
    let length = digits.len() / 2;
    if length > crate::MAX_FRAME_LEN {
        return Err(too_long(path, length));
    }
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16);
            let low = (pair[1] as char).to_digit(16);
            match (high, low) {
                // Each digit is below 16, so the octet fits.
                (Some(high), Some(low)) => Ok(u8::try_from(high << 4 | low).unwrap_or(0)),
                _ => Err(ScenarioError::new(Code::InvalidHex, path)),
            }
        })
        .collect()
}

fn too_long(path: &[PathSegment], actual: usize) -> ScenarioError {
    ScenarioError::bounded(
        Code::FrameTooLong,
        path,
        crate::MAX_FRAME_LEN as u64,
        actual as u64,
    )
}

fn payload(
    hex_value: Option<&str>,
    ascii_value: Option<&str>,
    at: &Cursor,
) -> Result<Vec<u8>, ScenarioError> {
    match (hex_value, ascii_value) {
        (Some(_), Some(_)) => Err(at.error("payload-ascii", Code::ConflictingPayload)),
        (Some(value), None) => hex(value, &at.at("payload-hex")),
        (None, Some(value)) => {
            let path = at.at("payload-ascii");
            if value.len() > crate::MAX_FRAME_LEN {
                return Err(too_long(&path, value.len()));
            }
            if !value
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
            {
                return Err(ScenarioError::new(Code::InvalidAscii, &path));
            }
            Ok(value.as_bytes().to_vec())
        }
        (None, None) => Ok(Vec::new()),
    }
}

fn ethernet(dto: &EthDto, at: &Cursor) -> Result<EthernetSpec, ScenarioError> {
    let at = at.child("eth");
    Ok(EthernetSpec {
        destination: mac(&dto.dst, &at.at("dst"))?,
        source: mac(&dto.src, &at.at("src"))?,
    })
}

fn ip(dto: &IpDto, at: &Cursor) -> Result<Ipv4Spec, ScenarioError> {
    let at = at.child("ip");
    Ok(Ipv4Spec {
        source: ipv4(&dto.src, &at.at("src"))?,
        destination: ipv4(&dto.dst, &at.at("dst"))?,
        ttl: dto.ttl.unwrap_or(64),
        identification: dto.id.unwrap_or(0),
        tos: dto.tos.unwrap_or(0),
        reserved_flag: dto.reserved.unwrap_or(false),
        dont_fragment: dto.df.unwrap_or(true),
        more_fragments: dto.mf.unwrap_or(false),
        fragment_offset: dto.fragment_offset.unwrap_or(0),
    })
}

fn echo_kind(op: OpDto) -> IcmpEchoKind {
    match op {
        OpDto::Request => IcmpEchoKind::Request,
        OpDto::Reply => IcmpEchoKind::Reply,
    }
}

fn tcp_flags(flags: &[TcpFlagDto], at: &Cursor) -> Result<TcpFlags, ScenarioError> {
    let mut out = TcpFlags::default();
    for flag in flags {
        let slot = match flag {
            TcpFlagDto::Fin => &mut out.fin,
            TcpFlagDto::Syn => &mut out.syn,
            TcpFlagDto::Rst => &mut out.rst,
            TcpFlagDto::Psh => &mut out.psh,
            TcpFlagDto::Ack => &mut out.ack,
        };
        if *slot {
            return Err(at.error("flags", Code::DuplicateTcpFlag));
        }
        *slot = true;
    }
    Ok(out)
}

fn frame(value: Value, at: &Cursor) -> Result<Frame, ScenarioError> {
    let (kind, body) = split_kind(value, at)?;
    let mut pad_to_min = false;
    let spec = match kind.as_str() {
        "raw" => {
            let raw: RawDto = decode(body, &at.0)?;
            FrameSpec::Raw(hex(&raw.hex, &at.at("hex"))?)
        }
        "ethernet" => {
            let eth: EthernetFrameDto = decode(body, &at.0)?;
            pad_to_min = eth.pad_to_min;
            FrameSpec::Ethernet {
                ethernet: ethernet(&eth.eth, at)?,
                ether_type: eth.ether_type,
                payload: payload(eth.payload_hex.as_deref(), eth.payload_ascii.as_deref(), at)?,
            }
        }
        "arp" => {
            let arp: ArpDto = decode(body, &at.0)?;
            pad_to_min = arp.pad_to_min;
            FrameSpec::Arp(ArpSpec {
                ethernet: ethernet(&arp.eth, at)?,
                operation: match arp.op {
                    OpDto::Request => ArpOperation::Request,
                    OpDto::Reply => ArpOperation::Reply,
                },
                sender_mac: mac(&arp.sender_mac, &at.at("sender-mac"))?,
                sender_ip: ipv4(&arp.sender_ip, &at.at("sender-ip"))?,
                target_mac: match &arp.target_mac {
                    Some(value) => mac(value, &at.at("target-mac"))?,
                    None => MacAddress([0; 6]),
                },
                target_ip: ipv4(&arp.target_ip, &at.at("target-ip"))?,
            })
        }
        "ipv4" => {
            let v4: Ipv4FrameDto = decode(body, &at.0)?;
            pad_to_min = v4.pad_to_min;
            FrameSpec::Ipv4 {
                ethernet: ethernet(&v4.eth, at)?,
                ipv4: ip(&v4.ip, at)?,
                protocol: v4.protocol,
                payload: payload(v4.payload_hex.as_deref(), v4.payload_ascii.as_deref(), at)?,
            }
        }
        "icmp-echo" => {
            let echo: IcmpEchoDto = decode(body, &at.0)?;
            pad_to_min = echo.pad_to_min;
            FrameSpec::IcmpEcho {
                ethernet: ethernet(&echo.eth, at)?,
                ipv4: ip(&echo.ip, at)?,
                kind: echo_kind(echo.op),
                identifier: echo.id,
                sequence: echo.seq,
                payload: payload(
                    echo.payload_hex.as_deref(),
                    echo.payload_ascii.as_deref(),
                    at,
                )?,
            }
        }
        "udp" => {
            let udp: UdpDto = decode(body, &at.0)?;
            pad_to_min = udp.pad_to_min;
            FrameSpec::Udp {
                ethernet: ethernet(&udp.eth, at)?,
                ipv4: ip(&udp.ip, at)?,
                source_port: udp.src_port,
                destination_port: udp.dst_port,
                zero_checksum: udp.zero_checksum,
                payload: payload(udp.payload_hex.as_deref(), udp.payload_ascii.as_deref(), at)?,
            }
        }
        "tcp" => {
            let tcp: TcpDto = decode(body, &at.0)?;
            pad_to_min = tcp.pad_to_min;
            FrameSpec::Tcp {
                ethernet: ethernet(&tcp.eth, at)?,
                ipv4: ip(&tcp.ip, at)?,
                source_port: tcp.src_port,
                destination_port: tcp.dst_port,
                sequence: tcp.seq,
                acknowledgment: tcp.ack,
                flags: tcp_flags(&tcp.flags, at)?,
                window: tcp.window.unwrap_or(65_535),
                payload: payload(tcp.payload_hex.as_deref(), tcp.payload_ascii.as_deref(), at)?,
            }
        }
        _ => return Err(at.error("kind", Code::UnknownKind)),
    };
    let built = spec.build().map_err(|error| match error {
        FrameBuildError::TooLong { actual, .. } => too_long(&at.0, actual),
        FrameBuildError::FragmentOffsetOutOfRange => ScenarioError::new(
            Code::FragmentOffsetOutOfRange,
            &at.child("ip").at("fragment-offset"),
        ),
    })?;
    Ok(if pad_to_min {
        built.padded_to_ethernet_min()
    } else {
        built
    })
}

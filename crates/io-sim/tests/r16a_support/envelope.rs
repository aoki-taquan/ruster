use std::fmt;

pub const ENVELOPE_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 72;
pub const MAX_ENVELOPE_LEN: usize = 131_072;
pub const MAX_PAYLOAD_LEN: usize = MAX_ENVELOPE_LEN - HEADER_LEN;
pub const MAX_CORPUS_CASES: usize = 512;
pub const MAX_CASES_PER_RUN: u64 = 65_536;
pub const MAX_RESOLUTION_NOW: u64 = u64::MAX - 1_000_064;

const MAGIC: [u8; 4] = *b"R16A";
const EXPECTED_LEN: usize = 32;
const EXPECTED_OFFSET: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Target {
    Parser = 1,
    Checksum = 2,
    Admission = 3,
    Resolution = 4,
}

impl Target {
    pub const ALL: [Self; 4] = [
        Self::Parser,
        Self::Checksum,
        Self::Admission,
        Self::Resolution,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Checksum => "checksum",
            Self::Admission => "admission",
            Self::Resolution => "resolution",
        }
    }

    pub fn from_name(name: &str) -> Result<Self, EnvelopeError> {
        match name {
            "parser" => Ok(Self::Parser),
            "checksum" => Ok(Self::Checksum),
            "admission" => Ok(Self::Admission),
            "resolution" => Ok(Self::Resolution),
            _ => Err(EnvelopeError::UnknownTargetName),
        }
    }

    fn from_tag(tag: u8) -> Result<Self, EnvelopeError> {
        match tag {
            1 => Ok(Self::Parser),
            2 => Ok(Self::Checksum),
            3 => Ok(Self::Admission),
            4 => Ok(Self::Resolution),
            _ => Err(EnvelopeError::UnknownTargetTag),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DropCode(u16);

impl DropCode {
    pub fn new(value: u16) -> Result<Self, EnvelopeError> {
        if (1..=145).contains(&value) {
            Ok(Self(value))
        } else {
            Err(EnvelopeError::UnknownDropCode)
        }
    }

    pub const fn value(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserAccept {
    pub header_len: u8,
    pub total_len: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub checksum: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResolutionSummary {
    pub pending_states: u16,
    pub pending_actions: u16,
    pub dynamic_neighbors: u16,
    pub queued: u32,
    pub suppressed: u32,
    pub state_full: u32,
    pub action_full: u32,
    pub clock_regressions: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expected {
    ParserAccept(ParserAccept),
    Drop(DropCode),
    Checksum(u16),
    AdmissionTx,
    Resolution(ResolutionSummary),
}

impl Expected {
    const fn tag(self) -> u8 {
        match self {
            Self::ParserAccept(_) => 1,
            Self::Drop(_) => 2,
            Self::Checksum(_) => 3,
            Self::AdmissionTx => 4,
            Self::Resolution(_) => 5,
        }
    }

    fn valid_for(self, target: Target) -> bool {
        matches!(
            (target, self),
            (Target::Parser, Self::ParserAccept(_) | Self::Drop(_))
                | (Target::Checksum, Self::Checksum(_))
                | (Target::Admission, Self::Drop(_) | Self::AdmissionTx)
                | (Target::Resolution, Self::Resolution(_))
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseEnvelope<'a> {
    pub target: Target,
    pub seed: u64,
    pub case_index: u64,
    pub now: u64,
    pub ingress: u16,
    pub expected: Expected,
    pub payload: &'a [u8],
}

impl CaseEnvelope<'_> {
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        if !self.expected.valid_for(self.target) {
            return Err(EnvelopeError::ExpectedTargetMismatch);
        }
        if self.case_index >= MAX_CASES_PER_RUN {
            return Err(EnvelopeError::CaseIndexOutOfRange);
        }
        if self.target == Target::Resolution && self.now > MAX_RESOLUTION_NOW {
            return Err(EnvelopeError::ResolutionTimeOutOfRange);
        }
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::PayloadTooLarge);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| EnvelopeError::PayloadTooLarge)?;
        let mut encoded = vec![0_u8; HEADER_LEN + self.payload.len()];
        encoded[0..4].copy_from_slice(&MAGIC);
        encoded[4] = ENVELOPE_VERSION;
        encoded[5] = self.target as u8;
        encoded[6] = self.expected.tag();
        encoded[8..16].copy_from_slice(&self.seed.to_le_bytes());
        encoded[16..24].copy_from_slice(&self.case_index.to_le_bytes());
        encoded[24..32].copy_from_slice(&self.now.to_le_bytes());
        encoded[32..34].copy_from_slice(&self.ingress.to_le_bytes());
        encoded[36..40].copy_from_slice(&payload_len.to_le_bytes());
        encode_expected(
            self.expected,
            &mut encoded[EXPECTED_OFFSET..EXPECTED_OFFSET + EXPECTED_LEN],
        );
        encoded[HEADER_LEN..].copy_from_slice(self.payload);
        Ok(encoded)
    }
}

pub fn parse(encoded: &[u8]) -> Result<CaseEnvelope<'_>, EnvelopeError> {
    if encoded.len() > MAX_ENVELOPE_LEN {
        return Err(EnvelopeError::EnvelopeTooLarge);
    }
    if encoded.len() < HEADER_LEN {
        return Err(EnvelopeError::HeaderTruncated);
    }
    if encoded[0..4] != MAGIC {
        return Err(EnvelopeError::BadMagic);
    }
    if encoded[4] != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    let target = Target::from_tag(encoded[5])?;
    if encoded[7] != 0 || encoded[34..36] != [0; 2] {
        return Err(EnvelopeError::ReservedNotZero);
    }
    let payload_len =
        usize::try_from(read_u32(encoded, 36)?).map_err(|_| EnvelopeError::PayloadTooLarge)?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(EnvelopeError::PayloadTooLarge);
    }
    let exact_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(EnvelopeError::EnvelopeTooLarge)?;
    if encoded.len() != exact_len {
        return Err(EnvelopeError::LengthMismatch);
    }
    let expected_bytes = &encoded[EXPECTED_OFFSET..EXPECTED_OFFSET + EXPECTED_LEN];
    let expected = decode_expected(encoded[6], expected_bytes)?;
    if !expected.valid_for(target) {
        return Err(EnvelopeError::ExpectedTargetMismatch);
    }
    let case_index = read_u64(encoded, 16)?;
    if case_index >= MAX_CASES_PER_RUN {
        return Err(EnvelopeError::CaseIndexOutOfRange);
    }
    let now = read_u64(encoded, 24)?;
    if target == Target::Resolution && now > MAX_RESOLUTION_NOW {
        return Err(EnvelopeError::ResolutionTimeOutOfRange);
    }
    Ok(CaseEnvelope {
        target,
        seed: read_u64(encoded, 8)?,
        case_index,
        now,
        ingress: read_u16(encoded, 32)?,
        expected,
        payload: &encoded[HEADER_LEN..],
    })
}

fn encode_expected(expected: Expected, bytes: &mut [u8]) {
    debug_assert_eq!(bytes.len(), EXPECTED_LEN);
    match expected {
        Expected::ParserAccept(value) => {
            bytes[0] = value.header_len;
            bytes[1..3].copy_from_slice(&value.total_len.to_le_bytes());
            bytes[3] = value.ttl;
            bytes[4] = value.protocol;
            bytes[5..9].copy_from_slice(&value.source);
            bytes[9..13].copy_from_slice(&value.destination);
            bytes[13..15].copy_from_slice(&value.checksum.to_le_bytes());
        }
        Expected::Drop(code) => bytes[0..2].copy_from_slice(&code.value().to_le_bytes()),
        Expected::Checksum(checksum) => bytes[0..2].copy_from_slice(&checksum.to_le_bytes()),
        Expected::AdmissionTx => {}
        Expected::Resolution(summary) => {
            bytes[0..2].copy_from_slice(&summary.pending_states.to_le_bytes());
            bytes[2..4].copy_from_slice(&summary.pending_actions.to_le_bytes());
            bytes[4..6].copy_from_slice(&summary.dynamic_neighbors.to_le_bytes());
            bytes[6..10].copy_from_slice(&summary.queued.to_le_bytes());
            bytes[10..14].copy_from_slice(&summary.suppressed.to_le_bytes());
            bytes[14..18].copy_from_slice(&summary.state_full.to_le_bytes());
            bytes[18..22].copy_from_slice(&summary.action_full.to_le_bytes());
            bytes[22..26].copy_from_slice(&summary.clock_regressions.to_le_bytes());
        }
    }
}

fn decode_expected(tag: u8, bytes: &[u8]) -> Result<Expected, EnvelopeError> {
    debug_assert_eq!(bytes.len(), EXPECTED_LEN);
    let (expected, used) = match tag {
        1 => (
            Expected::ParserAccept(ParserAccept {
                header_len: bytes[0],
                total_len: read_u16(bytes, 1)?,
                ttl: bytes[3],
                protocol: bytes[4],
                source: bytes[5..9].try_into().unwrap(),
                destination: bytes[9..13].try_into().unwrap(),
                checksum: read_u16(bytes, 13)?,
            }),
            15,
        ),
        2 => (Expected::Drop(DropCode::new(read_u16(bytes, 0)?)?), 2),
        3 => (Expected::Checksum(read_u16(bytes, 0)?), 2),
        4 => (Expected::AdmissionTx, 0),
        5 => (
            Expected::Resolution(ResolutionSummary {
                pending_states: read_u16(bytes, 0)?,
                pending_actions: read_u16(bytes, 2)?,
                dynamic_neighbors: read_u16(bytes, 4)?,
                queued: read_u32(bytes, 6)?,
                suppressed: read_u32(bytes, 10)?,
                state_full: read_u32(bytes, 14)?,
                action_full: read_u32(bytes, 18)?,
                clock_regressions: read_u32(bytes, 22)?,
            }),
            26,
        ),
        _ => return Err(EnvelopeError::UnknownExpectedTag),
    };
    if bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(EnvelopeError::NonCanonicalExpected);
    }
    Ok(expected)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EnvelopeError> {
    let word = bytes
        .get(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or(EnvelopeError::HeaderTruncated)?,
        )
        .ok_or(EnvelopeError::HeaderTruncated)?;
    Ok(u16::from_le_bytes(word.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EnvelopeError> {
    let word = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or(EnvelopeError::HeaderTruncated)?,
        )
        .ok_or(EnvelopeError::HeaderTruncated)?;
    Ok(u32::from_le_bytes(word.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EnvelopeError> {
    let word = bytes
        .get(
            offset
                ..offset
                    .checked_add(8)
                    .ok_or(EnvelopeError::HeaderTruncated)?,
        )
        .ok_or(EnvelopeError::HeaderTruncated)?;
    Ok(u64::from_le_bytes(word.try_into().unwrap()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    HeaderTruncated,
    EnvelopeTooLarge,
    PayloadTooLarge,
    BadMagic,
    UnsupportedVersion,
    UnknownTargetTag,
    UnknownTargetName,
    UnknownExpectedTag,
    UnknownDropCode,
    ReservedNotZero,
    NonCanonicalExpected,
    ExpectedTargetMismatch,
    CaseIndexOutOfRange,
    ResolutionTimeOutOfRange,
    LengthMismatch,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

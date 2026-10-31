use std::fmt;

/// Stable machine-readable reason for rejecting a scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScenarioErrorCode {
    InputTooLarge,
    InvalidUtf8,
    InvalidToml,
    DuplicateField,
    MissingSchema,
    UnsupportedSchema,
    UnknownField,
    MissingField,
    InvalidType,
    UnknownKind,
    ListTooLong,
    InvalidPath,
    PathTooLong,
    AbsolutePath,
    PathEscapesBase,
    InvalidInterfaceName,
    InvalidMacAddress,
    InvalidIpv4Address,
    InvalidHex,
    InvalidAscii,
    ConflictingPayload,
    ConflictingTime,
    TimeRegression,
    TimeOverflow,
    TickCountOutOfRange,
    TooManyTicks,
    FrameTooLong,
    FragmentOffsetOutOfRange,
    DuplicateTcpFlag,
    UnknownReason,
    DuplicateReason,
    EmptyExpectation,
    ZeroGeneration,
    HoldNotLast,
}

/// One value-free component of a scenario source path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathSegment {
    /// A schema field name. Never a user-supplied key or value.
    Field(&'static str),
    /// A zero-based array index.
    Index(usize),
}

/// A redacted scenario rejection.
///
/// It holds only a stable code, a path made of schema field names and
/// indices, and numeric bounds. It never retains source text, paths from the
/// file, or parser messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScenarioError {
    code: ScenarioErrorCode,
    path: Vec<PathSegment>,
    limit: Option<u64>,
    actual: Option<u64>,
}

impl ScenarioError {
    pub(crate) fn new(code: ScenarioErrorCode, path: &[PathSegment]) -> Self {
        Self {
            code,
            path: path.to_vec(),
            limit: None,
            actual: None,
        }
    }

    pub(crate) fn bounded(
        code: ScenarioErrorCode,
        path: &[PathSegment],
        limit: u64,
        actual: u64,
    ) -> Self {
        Self {
            limit: Some(limit),
            actual: Some(actual),
            ..Self::new(code, path)
        }
    }

    #[must_use]
    pub const fn code(&self) -> ScenarioErrorCode {
        self.code
    }

    #[must_use]
    pub fn path(&self) -> &[PathSegment] {
        &self.path
    }

    #[must_use]
    pub const fn limit(&self) -> Option<u64> {
        self.limit
    }

    #[must_use]
    pub const fn actual(&self) -> Option<u64> {
        self.actual
    }
}

impl fmt::Display for ScenarioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "scenario rejected: {:?} at ", self.code)?;
        if self.path.is_empty() {
            formatter.write_str("<root>")?;
        }
        for (index, segment) in self.path.iter().enumerate() {
            match segment {
                PathSegment::Field(field) if index == 0 => formatter.write_str(field)?,
                PathSegment::Field(field) => write!(formatter, ".{field}")?,
                PathSegment::Index(position) => write!(formatter, "[{position}]")?,
            }
        }
        if let (Some(limit), Some(actual)) = (self.limit, self.actual) {
            write!(formatter, " (limit {limit}, actual {actual})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ScenarioError {}

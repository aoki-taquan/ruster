use std::fmt::{self, Write};

/// Stable machine-readable reason for rejecting configuration input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiagnosticCode {
    InputTooLarge,
    InvalidUtf8,
    InvalidToml,
    DuplicateField,
    MissingSchemaVersion,
    InvalidSchemaVersion,
    UnsupportedSchemaVersion,
    ForbiddenField,
    UnknownField,
    MissingField,
    InvalidType,
    ListTooLong,
}

/// One safe component of a configuration source path.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathSegment {
    /// A schema field name. Configuration values are never stored here.
    Field(String),
    /// A zero-based array index.
    Index(usize),
}

/// A value-free path to the rejected configuration field or list entry.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SourcePath {
    segments: Vec<PathSegment>,
}

impl SourcePath {
    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    pub(crate) fn root_field(field: impl Into<String>) -> Self {
        Self {
            segments: vec![PathSegment::Field(field.into())],
        }
    }

    pub(crate) fn push_field(&mut self, field: impl Into<String>) {
        self.segments.push(PathSegment::Field(field.into()));
    }

    pub(crate) fn push_index(&mut self, index: usize) {
        self.segments.push(PathSegment::Index(index));
    }

    pub(crate) fn pop(&mut self) {
        self.segments.pop();
    }
}

impl fmt::Display for SourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            return formatter.write_str("<input>");
        }

        let mut has_field = false;
        for segment in &self.segments {
            match segment {
                PathSegment::Field(field) => {
                    if has_field {
                        formatter.write_str(".")?;
                    }
                    formatter.write_str(field)?;
                    has_field = true;
                }
                PathSegment::Index(index) => {
                    write!(formatter, "[{index}]")?;
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for SourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(&self.segments).finish()
    }
}

/// A redacted configuration rejection.
///
/// `Debug` contains only the stable code, value-free path, and numeric list
/// bounds. It never retains the source text or a parser error string.
#[derive(Clone, Eq, PartialEq)]
pub struct Diagnostic {
    code: DiagnosticCode,
    path: SourcePath,
    limit: Option<usize>,
    actual: Option<usize>,
    unknown_field: Option<String>,
}

impl Diagnostic {
    pub(crate) fn new(code: DiagnosticCode, path: SourcePath) -> Self {
        Self {
            code,
            path,
            limit: None,
            actual: None,
            unknown_field: None,
        }
    }

    pub(crate) fn bounded(
        code: DiagnosticCode,
        path: SourcePath,
        limit: usize,
        actual: usize,
    ) -> Self {
        Self {
            code,
            path,
            limit: Some(limit),
            actual: Some(actual),
            unknown_field: None,
        }
    }

    pub(crate) fn with_unknown_field(path: SourcePath, field: String) -> Self {
        Self {
            code: DiagnosticCode::UnknownField,
            path,
            limit: None,
            actual: None,
            unknown_field: Some(field),
        }
    }

    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        self.code
    }

    #[must_use]
    pub const fn path(&self) -> &SourcePath {
        &self.path
    }

    #[must_use]
    pub const fn limit(&self) -> Option<usize> {
        self.limit
    }

    #[must_use]
    pub const fn actual(&self) -> Option<usize> {
        self.actual
    }

    #[must_use]
    pub fn unknown_field(&self) -> Option<&str> {
        self.unknown_field.as_deref()
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "configuration invalid at {}: ", self.path)?;
        match self.code {
            DiagnosticCode::InputTooLarge => match (self.limit, self.actual) {
                (Some(limit), Some(actual)) => {
                    write!(
                        formatter,
                        "input exceeds {limit} bytes (read at least {actual})"
                    )
                }
                _ => formatter.write_str("input exceeds the configured size limit"),
            },
            DiagnosticCode::InvalidUtf8 => formatter.write_str("input is not valid UTF-8"),
            DiagnosticCode::InvalidToml => formatter.write_str("invalid TOML syntax"),
            DiagnosticCode::DuplicateField => formatter.write_str("duplicate field"),
            DiagnosticCode::MissingSchemaVersion => {
                formatter.write_str("schema-version is required")
            }
            DiagnosticCode::InvalidSchemaVersion => {
                formatter.write_str("schema-version must be an integer")
            }
            DiagnosticCode::UnsupportedSchemaVersion => {
                formatter.write_str("schema-version is not supported")
            }
            DiagnosticCode::ForbiddenField => formatter.write_str("field is not allowed"),
            DiagnosticCode::UnknownField => {
                formatter.write_str("unknown field")?;
                if let Some(field) = self.unknown_field.as_deref() {
                    formatter.write_str(" ")?;
                    formatter.write_char('"')?;
                    for character in field.escape_default() {
                        formatter.write_char(character)?;
                    }
                    formatter.write_char('"')?;
                }
                Ok(())
            }
            DiagnosticCode::MissingField => formatter.write_str("required field is missing"),
            DiagnosticCode::InvalidType => formatter.write_str("value has the wrong type"),
            DiagnosticCode::ListTooLong => match (self.limit, self.actual) {
                (Some(limit), Some(actual)) => {
                    write!(formatter, "list has {actual} entries; maximum is {limit}")
                }
                _ => formatter.write_str("list is too long"),
            },
        }
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Diagnostic")
            .field("code", &self.code)
            .field("path", &self.path)
            .field("limit", &self.limit)
            .field("actual", &self.actual)
            .finish()
    }
}

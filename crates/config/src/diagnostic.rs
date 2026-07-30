use std::fmt;

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
}

impl Diagnostic {
    pub(crate) fn new(code: DiagnosticCode, path: SourcePath) -> Self {
        Self {
            code,
            path,
            limit: None,
            actual: None,
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

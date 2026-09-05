use std::env;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ruster_bench::{
    deterministic_smoke, run, validate_deterministic_smoke_artifact, CountingAllocator,
    OutputFormat, ResultRow, RunConfig, Suite, R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES,
    R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS,
};

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

struct CliOptions {
    config: RunConfig,
    format: OutputFormat,
    logical_time_ms: u64,
    validate_artifact: Option<String>,
}

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ruster-bench: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let first = arguments.next();
    if first.as_deref() == Some("--snapshot-benchmark-file") {
        let input = next_value(&mut arguments, "--snapshot-benchmark-file")?;
        let output = next_value(&mut arguments, "--snapshot-benchmark-file")?;
        if arguments.next().is_some() {
            return Err("--snapshot-benchmark-file accepts exactly two paths".to_owned());
        }
        snapshot_benchmark_file(&input, &output)?;
        return Ok(());
    }
    if first.as_deref() == Some("--parse-benchmark-identity") {
        let path = next_value(&mut arguments, "--parse-benchmark-identity")?;
        if arguments.next().is_some() {
            return Err("--parse-benchmark-identity accepts exactly one path".to_owned());
        }
        let bytes = read_bounded_file(Path::new(&path), BENCHMARK_SOURCE_MAX_BYTES)
            .map_err(|error| format_benchmark_source_error(error, "identity source"))?;
        let (compiled, typed) = parse_identity_source_file(Path::new(&path), &bytes)?;
        println!("benchmark_compiled_sha256={compiled}");
        println!("benchmark_typed_sha256={typed}");
        return Ok(());
    }

    let Some(options) = parse_args(first.into_iter().chain(arguments))? else {
        return Ok(());
    };
    if let Some(path) = options.validate_artifact {
        let artifact = read_bounded_artifact(&path)?;
        validate_deterministic_smoke_artifact(&artifact).map_err(|error| error.to_string())?;
        println!("validated deterministic smoke artifact");
        return Ok(());
    }

    let config = options.config;
    let format = options.format;
    if config.suite == Suite::DeterministicSmoke {
        if let Some(error) = deterministic_format_error(format) {
            return Err(error.to_owned());
        }
        let artifact = deterministic_smoke(config.seed, options.logical_time_ms)
            .map_err(|error| error.to_string())?;
        print!("{artifact}");
        return Ok(());
    }

    let rows = run(&config).map_err(|error| error.to_string())?;
    if matches!(format, OutputFormat::Human | OutputFormat::Both) {
        println!(
            "# ruster-bench schema=1 suite={} seed={} samples={} sample_ms={} warmup_ms={}",
            suite_name(config.suite),
            config.seed,
            config.samples,
            config.sample_time.as_millis(),
            config.warmup_time.as_millis(),
        );
        println!("{}", ResultRow::human_header());
        for row in &rows {
            println!("{}", row.to_human_line());
        }
    }
    if matches!(format, OutputFormat::JsonLines | OutputFormat::Both) {
        for row in &rows {
            println!("{}", row.to_json_line());
        }
    }
    Ok(())
}

fn deterministic_format_error(format: OutputFormat) -> Option<&'static str> {
    (format != OutputFormat::JsonLines)
        .then_some("deterministic-smoke requires --format jsonl; canonical output is JSONL")
}

fn read_bounded_artifact(path: &str) -> Result<String, String> {
    let bytes = read_bounded_file(Path::new(path), R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES)
        .map_err(format_artifact_input_error)?;
    String::from_utf8(bytes)
        .map_err(|_| "deterministic smoke artifact input is not valid UTF-8".to_owned())
}

const BENCHMARK_SOURCE_MAX_BYTES: usize = 64 * 1024;
const BENCHMARK_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedFileError {
    Inspect,
    NonRegular,
    Open,
    HandleInspect,
    HandleNonRegular,
    TooLarge { maximum: usize },
    Read,
    Changed,
}

fn format_artifact_input_error(error: BoundedFileError) -> String {
    match error {
        BoundedFileError::Inspect => "cannot inspect deterministic smoke artifact input".to_owned(),
        BoundedFileError::NonRegular => {
            "deterministic smoke artifact input must be a regular file".to_owned()
        }
        BoundedFileError::Open => "cannot open deterministic smoke artifact input".to_owned(),
        BoundedFileError::HandleInspect => {
            "cannot inspect deterministic smoke artifact handle".to_owned()
        }
        BoundedFileError::HandleNonRegular | BoundedFileError::Changed => {
            "deterministic smoke artifact input changed or is not a regular file".to_owned()
        }
        BoundedFileError::TooLarge { maximum } => {
            format!("deterministic smoke artifact input exceeds the {maximum}-byte limit")
        }
        BoundedFileError::Read => "cannot read deterministic smoke artifact input".to_owned(),
    }
}

fn format_benchmark_source_error(error: BoundedFileError, subject: &str) -> String {
    match error {
        BoundedFileError::Inspect => format!("cannot inspect {subject}"),
        BoundedFileError::NonRegular => format!("{subject} must be a regular file"),
        BoundedFileError::Open => format!("cannot open {subject}"),
        BoundedFileError::HandleInspect => format!("cannot inspect {subject} handle"),
        BoundedFileError::HandleNonRegular | BoundedFileError::Changed => {
            format!("{subject} changed or is not a regular file")
        }
        BoundedFileError::TooLarge { maximum } => {
            format!("{subject} exceeds the {maximum}-byte limit")
        }
        BoundedFileError::Read => format!("cannot read {subject}"),
    }
}

fn read_bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>, BoundedFileError> {
    read_bounded_file_inner(path, maximum, || {})
}

fn read_bounded_file_inner<F>(
    path: &Path,
    maximum: usize,
    after_read: F,
) -> Result<Vec<u8>, BoundedFileError>
where
    F: FnOnce(),
{
    let path_before = fs::symlink_metadata(path).map_err(|_| BoundedFileError::Inspect)?;
    if !path_before.file_type().is_file() {
        return Err(BoundedFileError::NonRegular);
    }

    let file = open_bounded_file(path).map_err(|_| BoundedFileError::Open)?;
    let handle_before = file
        .metadata()
        .map_err(|_| BoundedFileError::HandleInspect)?;
    if !handle_before.file_type().is_file() || !same_file_version(&path_before, &handle_before) {
        return Err(BoundedFileError::HandleNonRegular);
    }
    if handle_before.len() > maximum as u64 {
        return Err(BoundedFileError::TooLarge { maximum });
    }

    let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedFileError::Read)?;
    after_read();

    let handle_after = file
        .metadata()
        .map_err(|_| BoundedFileError::HandleInspect)?;
    let path_after = fs::symlink_metadata(path).map_err(|_| BoundedFileError::Changed)?;
    if !handle_after.file_type().is_file()
        || !same_file_version(&handle_before, &handle_after)
        || !path_after.file_type().is_file()
        || !same_file_version(&path_after, &handle_after)
    {
        return Err(BoundedFileError::Changed);
    }
    if bytes.len() > maximum {
        return Err(BoundedFileError::TooLarge { maximum });
    }

    let mut verification = Vec::with_capacity(bytes.len().saturating_add(1));
    (&file)
        .seek(SeekFrom::Start(0))
        .map_err(|_| BoundedFileError::Read)?;
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut verification)
        .map_err(|_| BoundedFileError::Read)?;
    let handle_verified = file
        .metadata()
        .map_err(|_| BoundedFileError::HandleInspect)?;
    if verification != bytes || !same_file_version(&handle_after, &handle_verified) {
        return Err(BoundedFileError::Changed);
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
// Linux/Android fcntl.h: O_NOFOLLOW=0x20000, O_NONBLOCK=0x800.
const R17_SAFE_INPUT_FLAGS: i32 = 0x20000 | 0x800;

#[cfg(any(target_os = "macos", target_os = "ios"))]
// Darwin fcntl.h: O_NOFOLLOW=0x100, O_NONBLOCK=0x4.
const R17_SAFE_INPUT_FLAGS: i32 = 0x100 | 0x4;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn open_bounded_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(R17_SAFE_INPUT_FLAGS)
        .open(path)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn open_bounded_file(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "R17 bounded input requires a no-follow platform",
    ))
}

#[cfg(unix)]
fn same_file_version(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_version(_left: &Metadata, _right: &Metadata) -> bool {
    false
}

fn snapshot_benchmark_file(input: &str, output: &str) -> Result<(), String> {
    let bytes = read_bounded_file(Path::new(input), BENCHMARK_SOURCE_MAX_BYTES)
        .map_err(|error| format_benchmark_source_error(error, "benchmark source input"))?;
    let mut snapshot = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| "cannot create benchmark source snapshot".to_owned())?;
    snapshot
        .write_all(&bytes)
        .map_err(|_| "cannot write benchmark source snapshot".to_owned())?;
    snapshot
        .flush()
        .map_err(|_| "cannot flush benchmark source snapshot".to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RustTokenKind {
    Word(String),
    StringLiteral(String),
    RawLiteral,
    Punctuation(char),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustToken {
    kind: RustTokenKind,
    start: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustDelimiter {
    Parenthesis,
    Bracket,
    Brace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustLexicalPosition {
    Neutral,
    Type,
    Expression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RustDeclarationKind {
    TypeAlias,
    Function,
    Record,
    Enum,
    Value,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GenericLifetimeScope {
    delimiter: Option<RustDelimiter>,
    angle_depth: usize,
    expression_angle_base_depth: Option<usize>,
    macro_tree: bool,
    where_clause: bool,
    in_block: bool,
    type_context: bool,
    enum_body: bool,
    closure_parameters: bool,
    position: RustLexicalPosition,
    generic_name_candidate: bool,
    annotation_colon_candidate: bool,
    annotation_list: bool,
    type_alias_declaration: bool,
    function_parameters_pending: bool,
    record_fields_pending: bool,
    enum_variants_pending: bool,
}

// Incremental lexer state: each emitted token is observed once, and a
// lifetime candidate reads only the current delimiter scope. No token prefix
// is retained or rescanned when the candidate is classified.
struct RustLexicalContext {
    scopes: Vec<GenericLifetimeScope>,
    delimiter_error: bool,
    macro_tree_pending: bool,
    declaration_name_pending: Option<RustDeclarationKind>,
    pending_colon_position: Option<RustLexicalPosition>,
    path_separator_pending: bool,
    lifetime_apostrophe_pending: bool,
    lifetime_name_candidate: bool,
    break_label_value_pending: bool,
}

impl Default for RustLexicalContext {
    fn default() -> Self {
        Self {
            scopes: vec![GenericLifetimeScope {
                delimiter: None,
                angle_depth: 0,
                expression_angle_base_depth: None,
                macro_tree: false,
                where_clause: false,
                in_block: false,
                type_context: false,
                enum_body: false,
                closure_parameters: false,
                position: RustLexicalPosition::Neutral,
                generic_name_candidate: false,
                annotation_colon_candidate: false,
                annotation_list: false,
                type_alias_declaration: false,
                function_parameters_pending: false,
                record_fields_pending: false,
                enum_variants_pending: false,
            }],
            delimiter_error: false,
            macro_tree_pending: false,
            declaration_name_pending: None,
            pending_colon_position: None,
            path_separator_pending: false,
            lifetime_apostrophe_pending: false,
            lifetime_name_candidate: false,
            break_label_value_pending: false,
        }
    }
}

impl RustLexicalContext {
    fn observe(&mut self, source: &[u8], previous_token: Option<&RustToken>, token: &RustToken) {
        if !punctuation(token, ':') {
            self.apply_pending_colon();
        }
        if !matches!(
            token.kind,
            RustTokenKind::Word(_) | RustTokenKind::Punctuation('\'')
        ) {
            self.lifetime_apostrophe_pending = false;
        }
        if !punctuation(token, ':') {
            self.lifetime_name_candidate = false;
        }
        if !matches!(
            token.kind,
            RustTokenKind::Word(_) | RustTokenKind::Punctuation('\'' | '<' | '|')
        ) {
            self.break_label_value_pending = false;
        }

        let parent_is_macro_tree = self.scopes.last().is_some_and(|scope| scope.macro_tree);
        match &token.kind {
            RustTokenKind::Punctuation('(') => {
                let (annotation_list, record_fields) = self.take_parenthesis_context();
                let parent_position = if record_fields {
                    RustLexicalPosition::Type
                } else {
                    self.current_position()
                };
                self.open(
                    RustDelimiter::Parenthesis,
                    parent_is_macro_tree || self.macro_tree_pending,
                    parent_position,
                    annotation_list,
                    false,
                );
            }
            RustTokenKind::Punctuation('[') => self.open(
                RustDelimiter::Bracket,
                parent_is_macro_tree || self.macro_tree_pending,
                self.current_position(),
                false,
                false,
            ),
            RustTokenKind::Punctuation('{') => {
                let (annotation_list, enum_body) = self.take_brace_context();
                let parent_position = if enum_body {
                    RustLexicalPosition::Type
                } else {
                    RustLexicalPosition::Expression
                };
                self.open(
                    RustDelimiter::Brace,
                    parent_is_macro_tree || self.macro_tree_pending,
                    parent_position,
                    annotation_list,
                    enum_body,
                );
            }
            RustTokenKind::Punctuation(')') => self.close(RustDelimiter::Parenthesis),
            RustTokenKind::Punctuation(']') => self.close(RustDelimiter::Bracket),
            RustTokenKind::Punctuation('}') => self.close(RustDelimiter::Brace),
            RustTokenKind::Punctuation('<') => {
                self.observe_less_than(source, previous_token, token.start)
            }
            RustTokenKind::Punctuation('>') => self.observe_greater_than(source, token.start),
            RustTokenKind::Punctuation('=') => self.observe_equals(),
            RustTokenKind::Punctuation(';') => self.observe_semicolon(),
            RustTokenKind::Punctuation(':') => {
                self.observe_colon(source, previous_token, token.start)
            }
            RustTokenKind::Punctuation(',') => self.observe_comma(),
            RustTokenKind::Punctuation('-') => self.observe_minus(source, token.start),
            RustTokenKind::Punctuation('&') => self.observe_ampersand(),
            RustTokenKind::Punctuation('+') => self.observe_plus(),
            RustTokenKind::Punctuation('|') => {
                self.observe_pipe(source, previous_token, token.start)
            }
            RustTokenKind::Punctuation('\'') => self.observe_apostrophe(previous_token),
            RustTokenKind::Punctuation('!') => {
                self.macro_tree_pending = previous_token.is_some_and(is_macro_name);
            }
            RustTokenKind::Word(word) => self.observe_word(word),
            _ => {
                self.clear_pending_path();
                if let Some(scope) = self.scopes.last_mut() {
                    scope.generic_name_candidate = false;
                }
                self.macro_tree_pending = false;
            }
        }
        if matches!(token.kind, RustTokenKind::Punctuation('(' | '[' | '{')) {
            self.macro_tree_pending = false;
        }
    }

    fn open(
        &mut self,
        delimiter: RustDelimiter,
        macro_tree: bool,
        parent_position: RustLexicalPosition,
        annotation_list: bool,
        enum_body: bool,
    ) {
        if delimiter == RustDelimiter::Brace && !macro_tree {
            if let Some(scope) = self.scopes.last_mut() {
                // A where-clause belongs to the item header. Its opening
                // body is the forward boundary at which that state ends.
                scope.where_clause = false;
            }
        }
        let in_block = self
            .scopes
            .last()
            .is_some_and(|scope| scope.in_block || delimiter == RustDelimiter::Brace);
        let position = if macro_tree {
            RustLexicalPosition::Neutral
        } else {
            parent_position
        };
        self.scopes.push(GenericLifetimeScope {
            delimiter: Some(delimiter),
            angle_depth: 0,
            expression_angle_base_depth: None,
            macro_tree,
            where_clause: false,
            in_block,
            type_context: position == RustLexicalPosition::Type,
            enum_body,
            closure_parameters: false,
            position,
            generic_name_candidate: false,
            annotation_colon_candidate: annotation_list,
            annotation_list,
            type_alias_declaration: false,
            function_parameters_pending: false,
            record_fields_pending: false,
            enum_variants_pending: false,
        });
        self.clear_pending_path();
    }

    fn current_position(&self) -> RustLexicalPosition {
        self.scopes
            .last()
            .map_or(RustLexicalPosition::Neutral, |scope| scope.position)
    }

    fn take_parenthesis_context(&mut self) -> (bool, bool) {
        let Some(scope) = self.scopes.last_mut() else {
            return (false, false);
        };
        if scope.angle_depth != 0 {
            return (false, false);
        }
        if scope.function_parameters_pending {
            scope.function_parameters_pending = false;
            return (true, false);
        }
        if scope.record_fields_pending {
            scope.record_fields_pending = false;
            return (false, true);
        }
        (false, false)
    }

    fn take_brace_context(&mut self) -> (bool, bool) {
        let Some(scope) = self.scopes.last_mut() else {
            return (false, false);
        };
        if scope.angle_depth != 0 {
            return (false, false);
        }
        if scope.record_fields_pending {
            scope.record_fields_pending = false;
            return (true, false);
        }
        if scope.enum_variants_pending {
            scope.enum_variants_pending = false;
            return (false, true);
        }
        if scope.enum_body && scope.position == RustLexicalPosition::Type {
            return (true, false);
        }
        (false, false)
    }

    fn apply_pending_colon(&mut self) {
        let Some(position) = self.pending_colon_position.take() else {
            return;
        };
        if let Some(scope) = self.scopes.last_mut() {
            scope.position = position;
            scope.generic_name_candidate = position == RustLexicalPosition::Type;
        }
    }

    fn close(&mut self, delimiter: RustDelimiter) {
        let Some(scope) = self.scopes.last() else {
            self.delimiter_error = true;
            return;
        };
        if scope.delimiter == Some(delimiter) && self.scopes.len() > 1 {
            if Self::scope_has_unfinished_state(scope) {
                self.delimiter_error = true;
            }
            let closed_macro_tree = scope.macro_tree;
            self.scopes.pop();
            if delimiter == RustDelimiter::Brace && !closed_macro_tree {
                let should_reset_parent = self
                    .scopes
                    .last()
                    .is_some_and(|parent| parent.angle_depth == 0 && !parent.type_context);
                let parent_has_unfinished_state = should_reset_parent
                    && self
                        .scopes
                        .last()
                        .is_some_and(Self::scope_has_unfinished_state);
                if parent_has_unfinished_state {
                    self.delimiter_error = true;
                } else if should_reset_parent {
                    if let Some(parent) = self.scopes.last_mut() {
                        parent.where_clause = false;
                        parent.position = RustLexicalPosition::Expression;
                        parent.expression_angle_base_depth = None;
                        parent.closure_parameters = false;
                        parent.generic_name_candidate = false;
                        parent.annotation_colon_candidate = parent.annotation_list;
                        parent.type_alias_declaration = false;
                        parent.function_parameters_pending = false;
                        parent.record_fields_pending = false;
                        parent.enum_variants_pending = false;
                    }
                }
                self.declaration_name_pending = None;
                self.pending_colon_position = None;
                self.clear_pending_path();
            }
        } else {
            self.delimiter_error = true;
        }
    }

    fn observe_less_than(
        &mut self,
        source: &[u8],
        previous_token: Option<&RustToken>,
        start: usize,
    ) {
        let expression_angle = self.expression_angle_open(source, previous_token);
        let generic = self.is_generic_angle_open(source, previous_token, start);
        self.break_label_value_pending = false;
        let Some(scope) = self.scopes.last_mut() else {
            return;
        };
        if generic {
            if expression_angle && scope.expression_angle_base_depth.is_none() {
                scope.expression_angle_base_depth = Some(scope.angle_depth);
            }
            scope.angle_depth = scope.angle_depth.saturating_add(1);
            scope.position = RustLexicalPosition::Type;
        } else {
            scope.position = RustLexicalPosition::Expression;
        }
        scope.generic_name_candidate = false;
        self.clear_pending_path();
    }

    fn is_generic_angle_open(
        &self,
        source: &[u8],
        previous_token: Option<&RustToken>,
        start: usize,
    ) -> bool {
        if is_adjacent_less_than_operator(source, start) {
            return false;
        }
        if self.path_separator_pending {
            return true;
        }
        let Some(scope) = self.scopes.last() else {
            return false;
        };
        if scope.macro_tree {
            return previous_token.is_some_and(|token| {
                !is_expression_end_in_macro(token) || word_is_type_like(token)
            });
        }
        if scope.position != RustLexicalPosition::Type
            && (self.break_label_value_pending
                || is_expression_qpath_prefix(source, previous_token))
        {
            return true;
        }
        if scope.position == RustLexicalPosition::Expression {
            return false;
        }
        if scope.position == RustLexicalPosition::Type
            || scope.generic_name_candidate
            || self.declaration_name_pending.is_some()
        {
            return previous_token.is_none_or(|token| !is_expression_end(token));
        }
        previous_token.is_some_and(|token| {
            word_is_type_like(token)
                || matches!(
                    &token.kind,
                    RustTokenKind::Word(word) if word == "for" || word == "impl"
                )
                || matches!(
                    token.kind,
                    RustTokenKind::Punctuation(
                        '(' | '[' | '{' | ',' | ':' | '=' | '&' | '|' | '+' | '*'
                    )
                )
        })
    }

    fn expression_angle_open(&self, source: &[u8], previous_token: Option<&RustToken>) -> bool {
        let position = self.current_position();
        (self.path_separator_pending && position == RustLexicalPosition::Expression)
            || (position != RustLexicalPosition::Type
                && (self.break_label_value_pending
                    || is_expression_qpath_prefix(source, previous_token)))
    }

    fn observe_greater_than(&mut self, source: &[u8], start: usize) {
        let Some(scope) = self.scopes.last_mut() else {
            return;
        };
        let previous_byte = start
            .checked_sub(1)
            .and_then(|index| source.get(index))
            .copied();
        let next_byte = source.get(start + 1).copied();
        let arrow = previous_byte == Some(b'-');
        let compound_operator = arrow
            || (next_byte == Some(b'=')
                && !(scope.angle_depth != 0 && scope.position == RustLexicalPosition::Type))
            || previous_byte == Some(b'=')
            || ((next_byte == Some(b'>') || previous_byte == Some(b'>'))
                && !(scope.angle_depth != 0 && scope.position == RustLexicalPosition::Type));
        if scope.angle_depth != 0 && !compound_operator {
            scope.angle_depth -= 1;
            if scope.expression_angle_base_depth == Some(scope.angle_depth) {
                scope.expression_angle_base_depth = None;
                scope.position = RustLexicalPosition::Expression;
            } else {
                scope.position = RustLexicalPosition::Type;
            }
        } else if arrow {
            scope.position = RustLexicalPosition::Type;
        } else {
            scope.position = RustLexicalPosition::Expression;
        }
        scope.generic_name_candidate = false;
        self.clear_pending_path();
    }

    fn observe_equals(&mut self) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.position =
                if scope.angle_depth != 0 || scope.where_clause || scope.type_alias_declaration {
                    RustLexicalPosition::Type
                } else {
                    RustLexicalPosition::Expression
                };
            scope.generic_name_candidate = false;
            scope.annotation_colon_candidate = false;
        }
        self.clear_pending_path();
    }

    fn observe_semicolon(&mut self) {
        if self
            .scopes
            .last()
            .is_some_and(Self::scope_has_unfinished_state)
        {
            self.delimiter_error = true;
        }
        if let Some(scope) = self.scopes.last_mut() {
            scope.where_clause = false;
            scope.position = RustLexicalPosition::Expression;
            scope.generic_name_candidate = false;
            scope.annotation_colon_candidate = scope.annotation_list;
            scope.type_alias_declaration = false;
            scope.function_parameters_pending = false;
            scope.record_fields_pending = false;
            scope.enum_variants_pending = false;
        }
        self.declaration_name_pending = None;
        self.pending_colon_position = None;
        self.clear_pending_path();
    }

    fn observe_colon(&mut self, source: &[u8], previous_token: Option<&RustToken>, start: usize) {
        let adjacent_colons = previous_token.is_some_and(|token| {
            punctuation(token, ':')
                && token.start.checked_add(1) == Some(start)
                && start >= 1
                && source.get(start - 1..=start) == Some(b"::".as_slice())
        });
        if adjacent_colons && self.pending_colon_position.take().is_some() {
            if let Some(scope) = self.scopes.last_mut() {
                scope.generic_name_candidate = true;
            }
            // The exact forward `::` state is retained so an immediately
            // following `<` can be classified as a turbofish before operator
            // handling, without rescanning any prior token prefix.
            self.path_separator_pending = true;
            self.lifetime_name_candidate = false;
            return;
        }

        self.apply_pending_colon();
        self.clear_pending_path();
        let Some(scope) = self.scopes.last_mut() else {
            return;
        };
        let label = self.lifetime_name_candidate
            && scope.in_block
            && scope.position == RustLexicalPosition::Expression;
        self.pending_colon_position = Some(
            if !label
                && (scope.position == RustLexicalPosition::Type || scope.annotation_colon_candidate)
            {
                RustLexicalPosition::Type
            } else {
                RustLexicalPosition::Expression
            },
        );
        scope.annotation_colon_candidate = false;
        scope.generic_name_candidate = false;
        self.lifetime_name_candidate = false;
    }

    fn observe_comma(&mut self) {
        self.clear_pending_path();
        if let Some(scope) = self.scopes.last_mut() {
            if scope.closure_parameters && scope.angle_depth == 0 {
                scope.position = RustLexicalPosition::Neutral;
                scope.generic_name_candidate = false;
                scope.annotation_colon_candidate = true;
                return;
            }
            scope.position = if scope.angle_depth != 0 || scope.where_clause || scope.type_context {
                RustLexicalPosition::Type
            } else {
                RustLexicalPosition::Expression
            };
            scope.generic_name_candidate = false;
            if scope.annotation_list && scope.angle_depth == 0 {
                scope.annotation_colon_candidate = true;
            }
        }
    }

    fn observe_minus(&mut self, source: &[u8], start: usize) {
        self.clear_pending_path();
        if let Some(scope) = self.scopes.last_mut() {
            scope.position = if source.get(start + 1) == Some(&b'>') {
                RustLexicalPosition::Type
            } else {
                RustLexicalPosition::Expression
            };
            scope.generic_name_candidate = false;
        }
    }

    fn observe_ampersand(&mut self) {
        self.clear_pending_path();
        if let Some(scope) = self.scopes.last_mut() {
            if scope.position != RustLexicalPosition::Type {
                scope.position = RustLexicalPosition::Expression;
            }
            scope.generic_name_candidate = false;
        }
    }

    fn observe_plus(&mut self) {
        self.clear_pending_path();
        if let Some(scope) = self.scopes.last_mut() {
            if scope.position != RustLexicalPosition::Type && !scope.where_clause {
                scope.position = RustLexicalPosition::Expression;
            } else {
                scope.position = RustLexicalPosition::Type;
            }
            scope.generic_name_candidate = false;
        }
    }

    fn observe_pipe(&mut self, source: &[u8], previous_token: Option<&RustToken>, start: usize) {
        self.pending_colon_position = None;
        self.clear_pending_path();
        let after_break_label = self.break_label_value_pending;
        self.break_label_value_pending = false;
        let Some(scope) = self.scopes.last_mut() else {
            return;
        };
        if scope.closure_parameters {
            scope.closure_parameters = false;
            scope.position = RustLexicalPosition::Expression;
            scope.annotation_colon_candidate = false;
        } else if !scope.macro_tree
            && (after_break_label
                || closure_parameter_list_start(source, scope.position, previous_token, start))
        {
            scope.closure_parameters = true;
            scope.position = RustLexicalPosition::Neutral;
            scope.annotation_colon_candidate = true;
        } else {
            scope.position = RustLexicalPosition::Expression;
            scope.annotation_colon_candidate = false;
        }
        scope.generic_name_candidate = false;
    }

    fn observe_word(&mut self, word: &str) {
        let after_path_separator = self.path_separator_pending;
        let after_apostrophe = self.lifetime_apostrophe_pending;
        let after_break_label = after_apostrophe && self.break_label_value_pending;
        self.clear_pending_path();
        self.lifetime_apostrophe_pending = false;
        self.lifetime_name_candidate = after_apostrophe;
        self.break_label_value_pending = after_break_label;

        if word == "where" {
            if let Some(scope) = self.scopes.last_mut() {
                scope.where_clause = true;
                scope.position = RustLexicalPosition::Type;
                scope.generic_name_candidate = false;
            }
            self.declaration_name_pending = None;
            return;
        }

        if word == "fn" && self.current_position() == RustLexicalPosition::Type {
            if let Some(scope) = self.scopes.last_mut() {
                scope.function_parameters_pending = true;
                scope.generic_name_candidate = false;
            }
            self.declaration_name_pending = None;
            return;
        }

        let declaration_kind = match word {
            "type" => Some(RustDeclarationKind::TypeAlias),
            "fn" => Some(RustDeclarationKind::Function),
            "struct" | "union" => Some(RustDeclarationKind::Record),
            "enum" => Some(RustDeclarationKind::Enum),
            "const" | "static" => Some(RustDeclarationKind::Value),
            "trait" => Some(RustDeclarationKind::Other),
            _ => None,
        };
        if let Some(kind) = declaration_kind {
            self.declaration_name_pending = Some(kind);
            if let Some(scope) = self.scopes.last_mut() {
                scope.generic_name_candidate = false;
                scope.position = RustLexicalPosition::Neutral;
            }
            return;
        }

        let numeric = word.as_bytes().first().is_some_and(u8::is_ascii_digit);
        let expression_keyword = matches!(
            word,
            "break"
                | "continue"
                | "else"
                | "if"
                | "in"
                | "let"
                | "loop"
                | "match"
                | "return"
                | "while"
        );
        let declaration = self.declaration_name_pending.take();
        if let Some(scope) = self.scopes.last_mut() {
            if scope.closure_parameters && scope.position != RustLexicalPosition::Type {
                scope.position = RustLexicalPosition::Neutral;
                scope.generic_name_candidate = false;
                scope.annotation_colon_candidate = true;
            } else if numeric || expression_keyword {
                scope.position = RustLexicalPosition::Expression;
                scope.generic_name_candidate = false;
                if word == "let" {
                    scope.annotation_colon_candidate = true;
                }
            } else if let Some(kind) = declaration {
                scope.position = RustLexicalPosition::Neutral;
                scope.generic_name_candidate = true;
                scope.annotation_colon_candidate = kind == RustDeclarationKind::Value;
                scope.type_alias_declaration = kind == RustDeclarationKind::TypeAlias;
                scope.function_parameters_pending = kind == RustDeclarationKind::Function;
                scope.record_fields_pending = kind == RustDeclarationKind::Record;
                scope.enum_variants_pending = kind == RustDeclarationKind::Enum;
            } else if matches!(word, "impl" | "for") {
                scope.position = RustLexicalPosition::Type;
                scope.generic_name_candidate = true;
            } else if after_path_separator || scope.position == RustLexicalPosition::Type {
                scope.generic_name_candidate = true;
            } else {
                scope.position = RustLexicalPosition::Expression;
                scope.generic_name_candidate = false;
            }
        }
    }

    fn observe_apostrophe(&mut self, previous_token: Option<&RustToken>) {
        self.pending_colon_position = None;
        self.clear_pending_path();
        self.lifetime_apostrophe_pending = true;
        self.lifetime_name_candidate = false;
        self.break_label_value_pending =
            previous_token.is_some_and(|token| token_word(token, "break"));
        if let Some(scope) = self.scopes.last_mut() {
            scope.generic_name_candidate = false;
        }
    }

    fn clear_pending_path(&mut self) {
        self.path_separator_pending = false;
    }

    fn scope_has_unfinished_state(scope: &GenericLifetimeScope) -> bool {
        !scope.macro_tree
            && (scope.angle_depth != 0
                || scope.expression_angle_base_depth.is_some()
                || scope.closure_parameters)
    }

    fn expression_position(&self) -> bool {
        self.pending_colon_position
            .or_else(|| self.scopes.last().map(|scope| scope.position))
            == Some(RustLexicalPosition::Expression)
    }

    fn lifetime_context(&self) -> bool {
        !self.delimiter_error
            && self.scopes.last().is_some_and(|scope| {
                let position = self.pending_colon_position.unwrap_or(scope.position);
                scope.macro_tree
                    || scope.where_clause
                    || (scope.angle_depth != 0 && position == RustLexicalPosition::Type)
            })
    }

    fn lifetime_position<M: LexerMetricsSink>(
        &self,
        previous_token: Option<&RustToken>,
        source: &str,
        lifetime_end: usize,
        metrics: &mut M,
    ) -> bool {
        if self.generic_lifetime_position(metrics) {
            return true;
        }
        let Some(scope) = self.scopes.last() else {
            return false;
        };
        if scope.in_block && source.as_bytes().get(lifetime_end) == Some(&b':') {
            return true;
        }
        let type_position =
            self.pending_colon_position.unwrap_or(scope.position) == RustLexicalPosition::Type;
        previous_token.is_some_and(|token| {
            token_word(token, "break")
                || token_word(token, "continue")
                || (type_position
                    && matches!(token.kind, RustTokenKind::Punctuation('&' | '+' | ':')))
        })
    }

    fn generic_lifetime_position<M: LexerMetricsSink>(&self, metrics: &mut M) -> bool {
        metrics.context_queried();
        self.lifetime_context()
    }
}

fn closure_parameter_list_start(
    source: &[u8],
    position: RustLexicalPosition,
    previous_token: Option<&RustToken>,
    start: usize,
) -> bool {
    position != RustLexicalPosition::Type
        && previous_token.is_none_or(|token| {
            let adjacent_pipe = punctuation(token, '|')
                && token.start.checked_add(1) == Some(start)
                && start >= 1
                && source.get(start - 1..=start) == Some(b"||".as_slice());
            !adjacent_pipe
                && (is_expression_qpath_prefix(source, Some(token))
                    || matches!(
                        &token.kind,
                        RustTokenKind::Word(word) if matches!(word.as_str(), "async" | "move")
                    ))
        })
}

fn is_expression_qpath_prefix(source: &[u8], previous_token: Option<&RustToken>) -> bool {
    previous_token.is_some_and(|token| {
        matches!(
            token.kind,
            RustTokenKind::Punctuation(
                '(' | '['
                    | '{'
                    | ','
                    | ';'
                    | ':'
                    | '='
                    | '&'
                    | '|'
                    | '+'
                    | '-'
                    | '*'
                    | '/'
                    | '%'
                    | '^'
                    | '!'
                    | '<'
                    | '>'
            )
        ) || matches!(
            &token.kind,
            RustTokenKind::Word(word)
                if matches!(
                    word.as_str(),
                    "break" | "if" | "in" | "match" | "return" | "while"
                )
        ) || is_range_endpoint_prefix(source, token)
    })
}

fn is_range_endpoint_prefix(source: &[u8], token: &RustToken) -> bool {
    punctuation(token, '.')
        && token
            .start
            .checked_sub(1)
            .and_then(|index| source.get(index))
            == Some(&b'.')
        && token
            .start
            .checked_sub(2)
            .and_then(|index| source.get(index))
            != Some(&b'.')
}

fn is_adjacent_less_than_operator(source: &[u8], start: usize) -> bool {
    let previous_less_than =
        start.checked_sub(1).and_then(|index| source.get(index)) == Some(&b'<');
    let exact_shift_then_qpath = previous_less_than
        && start.checked_sub(2).and_then(|index| source.get(index)) == Some(&b'<')
        && start.checked_sub(3).and_then(|index| source.get(index)) != Some(&b'<');
    matches!(source.get(start + 1), Some(b'=' | b'<'))
        || (previous_less_than && !exact_shift_then_qpath)
}

fn is_numeric_word(token: &RustToken) -> bool {
    matches!(&token.kind, RustTokenKind::Word(word) if word.as_bytes().first().is_some_and(u8::is_ascii_digit))
}

fn is_expression_end(token: &RustToken) -> bool {
    is_numeric_word(token)
        || matches!(
            token.kind,
            RustTokenKind::StringLiteral(_)
                | RustTokenKind::RawLiteral
                | RustTokenKind::Punctuation(')' | ']' | '}')
        )
}

fn is_expression_end_in_macro(token: &RustToken) -> bool {
    match &token.kind {
        RustTokenKind::Word(word) => word
            .as_bytes()
            .first()
            .is_none_or(|byte| !byte.is_ascii_uppercase()),
        _ => is_expression_end(token),
    }
}

fn word_is_type_like(token: &RustToken) -> bool {
    matches!(&token.kind, RustTokenKind::Word(word) if word.as_bytes().first().is_some_and(u8::is_ascii_uppercase))
}

fn is_macro_name(token: &RustToken) -> bool {
    matches!(&token.kind, RustTokenKind::Word(word) if !matches!(
        word.as_str(),
        "break" | "continue" | "else" | "for" | "if" | "match" | "return" | "while"
    ))
}

trait LexerMetricsSink {
    fn token_observed(&mut self);
    fn context_queried(&mut self);
}

struct NoopLexerMetrics;

impl LexerMetricsSink for NoopLexerMetrics {
    #[inline]
    fn token_observed(&mut self) {}

    #[inline]
    fn context_queried(&mut self) {}
}

#[cfg(test)]
#[derive(Debug, Default)]
struct CountingLexerMetrics {
    token_observations: usize,
    context_queries: usize,
}

#[cfg(test)]
impl LexerMetricsSink for CountingLexerMetrics {
    fn token_observed(&mut self) {
        self.token_observations = self.token_observations.saturating_add(1);
    }

    fn context_queried(&mut self) {
        self.context_queries = self.context_queries.saturating_add(1);
    }
}

fn parse_identity_source(bytes: &[u8]) -> Result<(String, String), String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "identity source is not valid UTF-8".to_owned())?;
    let tokens = tokenize_rust_source(source)?;
    let mut compiled = None;
    let mut typed = None;
    let mut brace_depth = 0_usize;
    let mut parenthesis_depth = 0_usize;
    let mut bracket_depth = 0_usize;
    let mut index = 0;
    while index < tokens.len() {
        if token_word(&tokens[index], "pub")
            && tokens
                .get(index + 1)
                .is_some_and(|token| token_word(token, "const"))
            && tokens.get(index + 2).is_some_and(|token| {
                token_word(token, "R17_BENCHMARK_SPEC_SHA256_HEX")
                    || token_word(token, "R17_BENCHMARK_SPEC_SHA256")
            })
        {
            if brace_depth != 0
                || parenthesis_depth != 0
                || bracket_depth != 0
                || !line_has_no_prefix(source, tokens[index].start)
            {
                return Err("identity declarations must be top-level and unindented".to_owned());
            }
            let end = tokens[index..]
                .iter()
                .position(|token| token.kind == RustTokenKind::Punctuation(';'))
                .map(|offset| index + offset)
                .ok_or_else(|| "identity declaration is missing its semicolon".to_owned())?;
            let declaration = &tokens[index..=end];
            let name = match &tokens[index + 2].kind {
                RustTokenKind::Word(name) => name.as_str(),
                _ => unreachable!("target declaration name is a word"),
            };
            if name == "R17_BENCHMARK_SPEC_SHA256_HEX" {
                if compiled.is_some() {
                    return Err(
                        "identity source must contain exactly one compiled R17 SHA-256 string"
                            .to_owned(),
                    );
                }
                compiled = Some(parse_compiled_declaration(declaration)?);
            } else {
                if typed.is_some() {
                    return Err(
                        "identity source must contain one complete typed 32-byte R17 SHA-256 array"
                            .to_owned(),
                    );
                }
                typed = Some(parse_typed_declaration(declaration)?);
            }
            index = end;
        }
        match tokens[index].kind {
            RustTokenKind::Punctuation('{') => brace_depth = brace_depth.saturating_add(1),
            RustTokenKind::Punctuation('}') => {
                if brace_depth == 0 {
                    return Err("identity source contains unbalanced delimiters".to_owned());
                }
                brace_depth -= 1;
            }
            RustTokenKind::Punctuation('(') => parenthesis_depth += 1,
            RustTokenKind::Punctuation(')') => {
                if parenthesis_depth == 0 {
                    return Err("identity source contains unbalanced delimiters".to_owned());
                }
                parenthesis_depth -= 1;
            }
            RustTokenKind::Punctuation('[') => bracket_depth += 1,
            RustTokenKind::Punctuation(']') => {
                if bracket_depth == 0 {
                    return Err("identity source contains unbalanced delimiters".to_owned());
                }
                bracket_depth -= 1;
            }
            _ => {}
        }
        index += 1;
    }
    if brace_depth != 0 || parenthesis_depth != 0 || bracket_depth != 0 {
        return Err("identity source contains unbalanced delimiters".to_owned());
    }
    let compiled = compiled.ok_or_else(|| {
        "identity source must contain exactly one compiled R17 SHA-256 string".to_owned()
    })?;
    let typed = typed.ok_or_else(|| {
        "identity source must contain one complete typed 32-byte R17 SHA-256 array".to_owned()
    })?;
    Ok((compiled, typed))
}

fn parse_identity_source_file(
    path: &Path,
    source_bytes: &[u8],
) -> Result<(String, String), String> {
    let lexical = parse_identity_source(source_bytes)?;
    let uses_expansion = identity_source_uses_expansion(source_bytes)?;
    if !uses_expansion {
        return Ok(lexical);
    }
    let compiled = compile_identity_source(path, source_bytes)?;
    if lexical != compiled
        || compiled.0 != ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX
        || compiled.1 != ruster_bench::R17_BENCHMARK_SPEC_SHA256.to_lower_hex()
    {
        return Err(
            "identity source contains R17 identities that differ after cfg/include expansion or from the compiled benchmark crate"
                .to_owned(),
        );
    }
    Ok(lexical)
}

fn identity_source_uses_expansion(source_bytes: &[u8]) -> Result<bool, String> {
    let source = std::str::from_utf8(source_bytes)
        .map_err(|_| "identity source is not valid UTF-8".to_owned())?;
    let tokens = tokenize_rust_source(source)?;
    let mut brace_depth = 0_usize;
    let mut parenthesis_depth = 0_usize;
    let mut bracket_depth = 0_usize;
    let mut identity_declaration_seen = false;
    let mut index = 0;
    while index < tokens.len() {
        let top_level = brace_depth == 0 && parenthesis_depth == 0 && bracket_depth == 0;
        if top_level
            && token_word(&tokens[index], "include")
            && tokens
                .get(index + 1)
                .is_some_and(|token| punctuation(token, '!'))
        {
            return Ok(true);
        }
        if top_level && !identity_declaration_seen && cfg_attribute_starts_at(&tokens, index) {
            return Ok(true);
        }
        if top_level
            && token_word(&tokens[index], "pub")
            && tokens
                .get(index + 1)
                .is_some_and(|token| token_word(token, "const"))
            && tokens.get(index + 2).is_some_and(|token| {
                token_word(token, "R17_BENCHMARK_SPEC_SHA256_HEX")
                    || token_word(token, "R17_BENCHMARK_SPEC_SHA256")
            })
            && identity_declaration_has_cfg_attribute(&tokens, index)
        {
            return Ok(true);
        }
        if top_level
            && token_word(&tokens[index], "pub")
            && tokens
                .get(index + 1)
                .is_some_and(|token| token_word(token, "const"))
            && tokens.get(index + 2).is_some_and(|token| {
                token_word(token, "R17_BENCHMARK_SPEC_SHA256_HEX")
                    || token_word(token, "R17_BENCHMARK_SPEC_SHA256")
            })
        {
            identity_declaration_seen = true;
        }
        match tokens[index].kind {
            RustTokenKind::Punctuation('{') => brace_depth = brace_depth.saturating_add(1),
            RustTokenKind::Punctuation('}') => {
                if brace_depth == 0 {
                    return Err("identity source contains unbalanced delimiters".to_owned());
                }
                brace_depth -= 1;
            }
            RustTokenKind::Punctuation('(') => parenthesis_depth += 1,
            RustTokenKind::Punctuation(')') => {
                if parenthesis_depth == 0 {
                    return Err("identity source contains unbalanced delimiters".to_owned());
                }
                parenthesis_depth -= 1;
            }
            RustTokenKind::Punctuation('[') => bracket_depth += 1,
            RustTokenKind::Punctuation(']') => {
                if bracket_depth == 0 {
                    return Err("identity source contains unbalanced delimiters".to_owned());
                }
                bracket_depth -= 1;
            }
            _ => {}
        }
        index += 1;
    }
    Ok(false)
}

fn cfg_attribute_starts_at(tokens: &[RustToken], index: usize) -> bool {
    if !tokens
        .get(index)
        .is_some_and(|token| punctuation(token, '#'))
    {
        return false;
    }
    let mut opening = index + 1;
    if tokens
        .get(opening)
        .is_some_and(|token| punctuation(token, '!'))
    {
        opening += 1;
    }
    tokens
        .get(opening)
        .is_some_and(|token| punctuation(token, '['))
        && tokens
            .get(opening + 1)
            .is_some_and(|token| token_word(token, "cfg") || token_word(token, "cfg_attr"))
}

fn identity_declaration_has_cfg_attribute(tokens: &[RustToken], declaration_index: usize) -> bool {
    let mut end = declaration_index;
    while end > 0 && punctuation(&tokens[end - 1], ']') {
        let mut cursor = end - 1;
        let mut square_depth = 1_usize;
        while cursor > 0 {
            cursor -= 1;
            match tokens[cursor].kind {
                RustTokenKind::Punctuation(']') => square_depth += 1,
                RustTokenKind::Punctuation('[') => {
                    square_depth -= 1;
                    if square_depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        if square_depth != 0 {
            return false;
        }
        if (cursor > 0 && punctuation(&tokens[cursor - 1], '#'))
            || (cursor > 1
                && punctuation(&tokens[cursor - 1], '!')
                && punctuation(&tokens[cursor - 2], '#'))
        {
            if tokens
                .get(cursor + 1)
                .is_some_and(|token| token_word(token, "cfg") || token_word(token, "cfg_attr"))
            {
                return true;
            }
            end = if punctuation(&tokens[cursor - 1], '#') {
                cursor - 1
            } else {
                cursor - 2
            };
        } else {
            break;
        }
    }
    false
}

fn compile_identity_source(path: &Path, source_bytes: &[u8]) -> Result<(String, String), String> {
    let source_path = fs::canonicalize(path).map_err(|_| {
        "identity source contains an R17 identity that could not be compiled".to_owned()
    })?;
    if !matches!(
        read_bounded_file(&source_path, BENCHMARK_SOURCE_MAX_BYTES),
        Ok(current) if current.as_slice() == source_bytes
    ) {
        return Err("identity source changed during R17 compilation".to_owned());
    }
    let source_path = source_path.to_str().ok_or_else(|| {
        "identity source contains an R17 identity with an unsupported path".to_owned()
    })?;
    let source_path = rust_string_literal(source_path);
    let mut wrapper = String::from(
        r#"#[derive(Clone, Copy)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[path = "#,
    );
    wrapper.push_str(&source_path);
    wrapper.push_str(
        r#"]
mod identity;

fn print_hex(bytes: &[u8; 32]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        print!(
            "{}{}",
            char::from(HEX[usize::from(byte >> 4)]),
            char::from(HEX[usize::from(byte & 0x0f)])
        );
    }
}

fn main() {
    println!(
        "benchmark_compiled_sha256={}",
        identity::R17_BENCHMARK_SPEC_SHA256_HEX
    );
    print!("benchmark_typed_sha256=");
    print_hex(identity::R17_BENCHMARK_SPEC_SHA256.as_bytes());
    println!();
}
"#,
    );

    let workspace = IdentityCompilationWorkspace::new()?;
    let wrapper_path = workspace.path.join("identity_wrapper.rs");
    let executable_path = workspace.path.join(if cfg!(windows) {
        "identity_wrapper.exe"
    } else {
        "identity_wrapper"
    });
    fs::write(&wrapper_path, wrapper).map_err(|_| {
        "identity source contains an R17 identity that could not be compiled".to_owned()
    })?;

    let compiler = env::var_os("R17_RUSTC")
        .or_else(|| env::var_os("RUSTC"))
        .unwrap_or_else(|| "rustc".into());
    let mut command = Command::new(compiler);
    command
        .arg("--edition=2021")
        .arg("--crate-type=bin")
        .arg("-o")
        .arg(&executable_path)
        .arg(&wrapper_path)
        .env("CARGO_MANIFEST_DIR", BENCHMARK_MANIFEST_DIR);
    if cfg!(debug_assertions) {
        command.arg("-C").arg("debug-assertions=yes");
    }
    let compilation = command.output().map_err(|_| {
        "identity source contains an R17 identity that could not be compiled".to_owned()
    })?;
    if !matches!(
        read_bounded_file(path, BENCHMARK_SOURCE_MAX_BYTES),
        Ok(current) if current.as_slice() == source_bytes
    ) {
        return Err("identity source changed during R17 compilation".to_owned());
    }
    if !compilation.status.success() {
        return Err(
            "identity source contains an R17 identity that could not be compiled".to_owned(),
        );
    }

    let execution = Command::new(&executable_path).output().map_err(|_| {
        "identity source contains an R17 identity that could not be evaluated".to_owned()
    })?;
    if !execution.status.success() {
        return Err(
            "identity source contains an R17 identity that could not be evaluated".to_owned(),
        );
    }
    parse_compiled_identity_output(&execution.stdout)
}

fn parse_compiled_identity_output(output: &[u8]) -> Result<(String, String), String> {
    let output = std::str::from_utf8(output).map_err(|_| {
        "identity source contains an R17 identity with invalid compiled output".to_owned()
    })?;
    let mut lines = output.lines();
    let compiled = lines
        .next()
        .and_then(|line| line.strip_prefix("benchmark_compiled_sha256="))
        .filter(|value| is_lower_hex(value, 64))
        .ok_or_else(|| {
            "identity source contains an R17 identity with invalid compiled output".to_owned()
        })?;
    let typed = lines
        .next()
        .and_then(|line| line.strip_prefix("benchmark_typed_sha256="))
        .filter(|value| is_lower_hex(value, 64))
        .ok_or_else(|| {
            "identity source contains an R17 identity with invalid compiled output".to_owned()
        })?;
    if lines.next().is_some() {
        return Err(
            "identity source contains an R17 identity with invalid compiled output".to_owned(),
        );
    }
    Ok((compiled.to_owned(), typed.to_owned()))
}

fn rust_string_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len().saturating_add(2));
    literal.push('"');
    for character in value.chars() {
        match character {
            '\\' => literal.push_str("\\\\"),
            '"' => literal.push_str("\\\""),
            _ if character.is_control() => literal.extend(character.escape_default()),
            _ => literal.push(character),
        }
    }
    literal.push('"');
    literal
}

struct IdentityCompilationWorkspace {
    path: std::path::PathBuf,
}

impl IdentityCompilationWorkspace {
    fn new() -> Result<Self, String> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let temporary_root = env::temp_dir();
        for _ in 0..128 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                temporary_root.join(format!("ruster-bench-identity-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => break,
            }
        }
        Err("identity source compiler workspace could not be created".to_owned())
    }
}

impl Drop for IdentityCompilationWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn token_word(token: &RustToken, expected: &str) -> bool {
    matches!(&token.kind, RustTokenKind::Word(value) if value == expected)
}

fn line_has_no_prefix(source: &str, offset: usize) -> bool {
    let line_start = source[..offset]
        .rfind('\n')
        .map_or(0, |position| position + 1);
    line_start == offset
}

fn parse_compiled_declaration(tokens: &[RustToken]) -> Result<String, String> {
    if tokens.len() != 9
        || !token_word(&tokens[0], "pub")
        || !token_word(&tokens[1], "const")
        || !token_word(&tokens[2], "R17_BENCHMARK_SPEC_SHA256_HEX")
        || !punctuation(&tokens[3], ':')
        || !punctuation(&tokens[4], '&')
        || !token_word(&tokens[5], "str")
        || !punctuation(&tokens[6], '=')
        || !punctuation(&tokens[8], ';')
    {
        return Err("compiled R17 SHA-256 declaration is malformed".to_owned());
    }
    let RustTokenKind::StringLiteral(value) = &tokens[7].kind else {
        return Err("compiled R17 SHA-256 must be lowercase 64-hex".to_owned());
    };
    if !is_lower_hex(value, 64) {
        return Err("compiled R17 SHA-256 must be lowercase 64-hex".to_owned());
    }
    Ok(value.clone())
}

fn parse_typed_declaration(tokens: &[RustToken]) -> Result<String, String> {
    let valid_prefix = tokens.len() >= 16
        && token_word(&tokens[0], "pub")
        && token_word(&tokens[1], "const")
        && token_word(&tokens[2], "R17_BENCHMARK_SPEC_SHA256")
        && punctuation(&tokens[3], ':')
        && token_word(&tokens[4], "Sha256Digest")
        && punctuation(&tokens[5], '=')
        && token_word(&tokens[6], "Sha256Digest")
        && punctuation(&tokens[7], ':')
        && punctuation(&tokens[8], ':')
        && token_word(&tokens[9], "from_bytes")
        && punctuation(&tokens[10], '(')
        && punctuation(&tokens[11], '[');
    if !valid_prefix {
        return Err("typed R17 SHA-256 declaration is malformed".to_owned());
    }

    let mut output = String::with_capacity(64);
    let mut index = 12;
    for _ in 0..32 {
        let Some(token) = tokens.get(index) else {
            return Err(
                "typed R17 SHA-256 bytes must use exact lowercase 0x[0-9a-f]{2} tokens and contain exactly 32 bytes"
                    .to_owned(),
            );
        };
        let RustTokenKind::Word(value) = &token.kind else {
            return Err(
                "typed R17 SHA-256 bytes must use exact lowercase 0x[0-9a-f]{2} tokens and contain exactly 32 bytes"
                    .to_owned(),
            );
        };
        if value.len() != 4 || !value.starts_with("0x") || !is_lower_hex(&value[2..], 2) {
            return Err(
                "typed R17 SHA-256 bytes must use exact lowercase 0x[0-9a-f]{2} tokens and contain exactly 32 bytes"
                    .to_owned(),
            );
        }
        output.push_str(&value[2..]);
        index += 1;
        if !tokens
            .get(index)
            .is_some_and(|token| punctuation(token, ','))
        {
            return Err(
                "typed R17 SHA-256 bytes must use exact lowercase 0x[0-9a-f]{2} tokens and contain exactly 32 bytes"
                    .to_owned(),
            );
        }
        index += 1;
    }
    if index + 3 != tokens.len()
        || !punctuation(&tokens[index], ']')
        || !punctuation(&tokens[index + 1], ')')
        || !punctuation(&tokens[index + 2], ';')
    {
        return Err(
            "typed R17 SHA-256 bytes must use exact lowercase 0x[0-9a-f]{2} tokens and contain exactly 32 bytes"
                .to_owned(),
        );
    }
    Ok(output)
}

fn punctuation(token: &RustToken, expected: char) -> bool {
    token.kind == RustTokenKind::Punctuation(expected)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiteralMode {
    NormalString,
    ByteString,
    RawString,
    RawByteString,
    Character,
    ByteCharacter,
}

const ERR_UNTERMINATED_STRING: &str = "identity source contains an unterminated string";
const ERR_MALFORMED_STRING: &str = "identity source contains a malformed string literal";
const ERR_MALFORMED_BYTE_STRING: &str = "identity source contains a malformed byte string literal";
const ERR_BARE_CR_STRING: &str = "identity source contains a bare CR in a string literal";
const ERR_UNTERMINATED_RAW: &str = "identity source contains an unterminated raw string literal";
const ERR_BARE_CR_RAW: &str = "identity source contains a bare CR in a raw string literal";
const ERR_NON_ASCII_RAW_BYTE: &str = "identity source contains a non-ASCII raw byte string literal";
const ERR_TOO_MANY_RAW_HASHES: &str =
    "identity source contains too many raw string delimiter hashes";
const ERR_UNTERMINATED_CHARACTER: &str =
    "identity source contains an unterminated character literal";
const ERR_MALFORMED_CHARACTER: &str = "identity source contains a malformed character literal";
const ERR_EMPTY_CHARACTER: &str = "identity source contains an empty character literal";
const ERR_UNTERMINATED_BYTE_CHARACTER: &str =
    "identity source contains an unterminated byte character literal";
const ERR_MALFORMED_BYTE_CHARACTER: &str =
    "identity source contains a malformed byte character literal";
const ERR_EMPTY_BYTE_CHARACTER: &str = "identity source contains an empty byte character literal";
const ERR_MALFORMED_RAW_IDENTIFIER: &str = "identity source contains a malformed raw identifier";
const ERR_INVALID_LITERAL_SUFFIX: &str = "identity source contains an invalid literal suffix";
const ERR_MALFORMED_NUMBER: &str = "identity source contains a malformed numeric literal";
const ERR_RESERVED_LITERAL_PREFIX: &str = "identity source contains a reserved literal prefix";
const ERR_UNKNOWN_TOKEN: &str = "identity source contains an unknown token";
const ERR_UNBALANCED_DELIMITERS: &str = "identity source contains unbalanced delimiters";

fn tokenize_rust_source(source: &str) -> Result<Vec<RustToken>, String> {
    let mut metrics = NoopLexerMetrics;
    tokenize_rust_source_inner(source, &mut metrics)
}

fn tokenize_rust_source_inner<M: LexerMetricsSink>(
    source: &str,
    metrics: &mut M,
) -> Result<Vec<RustToken>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut context = RustLexicalContext::default();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index = skip_block_comment(bytes, index)?;
            continue;
        }
        if bytes[index] == b'c' && bytes.get(index + 1) == Some(&b'r') {
            if let Some((_, end)) = raw_string_end(source, index + 1, false)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken {
                        kind: RustTokenKind::RawLiteral,
                        start: index,
                    },
                );
                index = end;
                continue;
            }
        }
        if bytes[index] == b'c' && bytes.get(index + 1) == Some(&b'"') {
            let (_, end) = normal_string_end(source, index + 1, false)?;
            push_token(
                &mut tokens,
                &mut context,
                bytes,
                metrics,
                RustToken {
                    kind: RustTokenKind::RawLiteral,
                    start: index,
                },
            );
            index = end;
            continue;
        }
        if bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'r') {
            if let Some((kind, end)) = scan_literal(source, index, LiteralMode::RawByteString)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken { kind, start: index },
                );
                index = end;
                continue;
            }
        }
        if bytes[index] == b'r' {
            if let Some((kind, end)) = scan_literal(source, index, LiteralMode::RawString)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken { kind, start: index },
                );
                index = end;
                continue;
            }
        }
        if bytes[index] == b'r' && bytes.get(index + 1) == Some(&b'#') {
            let start = index;
            let identifier_start = index + 2;
            let Some(end) = rust_identifier_end(source, identifier_start) else {
                return Err(ERR_MALFORMED_RAW_IDENTIFIER.to_owned());
            };
            if is_reserved_raw_identifier(&source[identifier_start..end]) {
                return Err(ERR_MALFORMED_RAW_IDENTIFIER.to_owned());
            }
            if reserved_literal_prefix_follows(bytes, end) {
                return Err(ERR_RESERVED_LITERAL_PREFIX.to_owned());
            }
            index = end;
            push_token(
                &mut tokens,
                &mut context,
                bytes,
                metrics,
                RustToken {
                    kind: RustTokenKind::Word(source[start..index].to_owned()),
                    start,
                },
            );
            continue;
        }
        if bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'\'') {
            if let Some((kind, end)) = scan_literal(source, index, LiteralMode::ByteCharacter)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken { kind, start: index },
                );
                index = end;
                continue;
            }
        }
        if bytes[index] == b'b' && bytes.get(index + 1) == Some(&b'"') {
            if let Some((kind, end)) = scan_literal(source, index, LiteralMode::ByteString)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken { kind, start: index },
                );
                index = end;
                continue;
            }
        }
        if bytes[index] == b'"' {
            if let Some((kind, end)) = scan_literal(source, index, LiteralMode::NormalString)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken { kind, start: index },
                );
                index = end;
                continue;
            }
        }
        if bytes[index] == b'\''
            && char_literal_candidate(source, index, tokens.last(), &context, metrics)
        {
            if let Some((kind, end)) = scan_literal(source, index, LiteralMode::Character)? {
                push_token(
                    &mut tokens,
                    &mut context,
                    bytes,
                    metrics,
                    RustToken { kind, start: index },
                );
                index = end;
                continue;
            }
        }
        if let Some(end) = rust_identifier_end(source, index) {
            let start = index;
            if reserved_literal_prefix_follows(bytes, end) {
                return Err(ERR_RESERVED_LITERAL_PREFIX.to_owned());
            }
            index = end;
            push_token(
                &mut tokens,
                &mut context,
                bytes,
                metrics,
                RustToken {
                    kind: RustTokenKind::Word(source[start..index].to_owned()),
                    start,
                },
            );
            continue;
        }
        if bytes[index].is_ascii_digit() {
            let start = index;
            index = numeric_literal_end(source, start)?;
            push_token(
                &mut tokens,
                &mut context,
                bytes,
                metrics,
                RustToken {
                    kind: RustTokenKind::Word(source[start..index].to_owned()),
                    start,
                },
            );
            continue;
        }
        let character = source[index..]
            .chars()
            .next()
            .ok_or_else(|| "identity source contains invalid UTF-8".to_owned())?;
        if !is_rust_punctuation(character) {
            return Err(ERR_UNKNOWN_TOKEN.to_owned());
        }
        let width = character.len_utf8();
        push_token(
            &mut tokens,
            &mut context,
            bytes,
            metrics,
            RustToken {
                kind: RustTokenKind::Punctuation(character),
                start: index,
            },
        );
        index += width;
    }
    if context.delimiter_error
        || context.scopes.len() != 1
        || context
            .scopes
            .iter()
            .any(RustLexicalContext::scope_has_unfinished_state)
    {
        return Err(ERR_UNBALANCED_DELIMITERS.to_owned());
    }
    Ok(tokens)
}

fn push_token<M: LexerMetricsSink>(
    tokens: &mut Vec<RustToken>,
    context: &mut RustLexicalContext,
    source: &[u8],
    metrics: &mut M,
    token: RustToken,
) {
    let previous_token = tokens.last();
    metrics.token_observed();
    context.observe(source, previous_token, &token);
    tokens.push(token);
}

fn reserved_literal_prefix_follows(source: &[u8], end: usize) -> bool {
    matches!(source.get(end), Some(b'"' | b'\'' | b'#'))
}

fn numeric_literal_end(source: &str, start: usize) -> Result<usize, String> {
    let bytes = source.as_bytes();
    let radix = match bytes.get(start..start + 2) {
        Some(b"0b") => Some(2_u8),
        Some(b"0o") => Some(8_u8),
        Some(b"0x") => Some(16_u8),
        _ => None,
    };
    let mut index;
    let float_literal;
    let radix_literal = radix.is_some();

    if let Some(radix) = radix {
        index = start + 2;
        let mut digits = 0_usize;
        while let Some(&byte) = bytes.get(index) {
            if byte == b'_' {
                index += 1;
            } else if ascii_digit_for_radix(byte, radix) {
                digits += 1;
                index += 1;
            } else {
                break;
            }
        }
        if digits == 0 || bytes.get(index).is_some_and(u8::is_ascii_digit) {
            return Err(ERR_MALFORMED_NUMBER.to_owned());
        }
        float_literal = false;
    } else {
        index = start;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
        {
            index += 1;
        }

        let mut has_fraction = false;
        if bytes.get(index) == Some(&b'.')
            && bytes.get(index + 1) != Some(&b'.')
            && source
                .get(index + 1..)
                .and_then(|tail| tail.chars().next())
                .is_none_or(|character| character != '_' && !is_rust_identifier_start(character))
        {
            has_fraction = true;
            index += 1;
            while bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
            {
                index += 1;
            }
        }

        let mut has_exponent = false;
        if matches!(bytes.get(index), Some(b'e' | b'E')) {
            has_exponent = true;
            index += 1;
            if matches!(bytes.get(index), Some(b'+' | b'-')) {
                index += 1;
            }
            let mut exponent_digits = 0_usize;
            while let Some(&byte) = bytes.get(index) {
                if byte == b'_' {
                    index += 1;
                } else if byte.is_ascii_digit() {
                    exponent_digits += 1;
                    index += 1;
                } else {
                    break;
                }
            }
            if exponent_digits == 0 {
                return Err(ERR_MALFORMED_NUMBER.to_owned());
            }
        }
        float_literal = has_fraction || has_exponent;
    }

    if let Some(suffix_end) = rust_identifier_end(source, index) {
        let suffix = &source[index..suffix_end];
        let valid = if radix_literal {
            is_integer_suffix(suffix)
        } else if float_literal {
            is_float_suffix(suffix)
        } else {
            is_integer_suffix(suffix) || is_float_suffix(suffix)
        };
        if !valid {
            return Err(ERR_INVALID_LITERAL_SUFFIX.to_owned());
        }
        index = suffix_end;
    }
    if source
        .get(index..)
        .and_then(|tail| tail.chars().next())
        .is_some_and(is_rust_identifier_continue)
    {
        return Err(ERR_INVALID_LITERAL_SUFFIX.to_owned());
    }
    if bytes.get(index) == Some(&b'.')
        && bytes.get(index + 1) == Some(&b'.')
        && bytes.get(index + 2) == Some(&b'.')
    {
        return Err(ERR_MALFORMED_NUMBER.to_owned());
    }
    Ok(index)
}

fn ascii_digit_for_radix(byte: u8, radix: u8) -> bool {
    match radix {
        2 => matches!(byte, b'0'..=b'1'),
        8 => matches!(byte, b'0'..=b'7'),
        16 => byte.is_ascii_hexdigit(),
        _ => false,
    }
}

fn is_integer_suffix(suffix: &str) -> bool {
    matches!(
        suffix,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn is_float_suffix(suffix: &str) -> bool {
    matches!(suffix, "f32" | "f64")
}

fn is_rust_punctuation(character: char) -> bool {
    matches!(
        character,
        '(' | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | ';'
            | ','
            | '.'
            | '@'
            | '#'
            | '~'
            | '?'
            | ':'
            | '$'
            | '='
            | '!'
            | '<'
            | '>'
            | '-'
            | '&'
            | '|'
            | '+'
            | '*'
            | '/'
            | '^'
            | '%'
            | '\''
    )
}

fn scan_literal(
    source: &str,
    start: usize,
    mode: LiteralMode,
) -> Result<Option<(RustTokenKind, usize)>, String> {
    match mode {
        LiteralMode::NormalString => {
            let (value, end) = normal_string_end(source, start, false)?;
            Ok(Some((RustTokenKind::StringLiteral(value), end)))
        }
        LiteralMode::ByteString => {
            let (_, end) = normal_string_end(source, start + 1, true)?;
            Ok(Some((RustTokenKind::RawLiteral, end)))
        }
        LiteralMode::RawString => raw_string_end(source, start, false),
        LiteralMode::RawByteString => raw_string_end(source, start + 1, true),
        LiteralMode::Character => Ok(Some((
            RustTokenKind::RawLiteral,
            char_literal_end(source, start)?,
        ))),
        LiteralMode::ByteCharacter => Ok(Some((
            RustTokenKind::RawLiteral,
            byte_char_literal_end(source, start + 1)?,
        ))),
    }
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> Result<usize, String> {
    let mut depth = 1_usize;
    index += 2;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            index += 2;
        } else if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth -= 1;
            index += 2;
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index += 1;
        }
    }
    Err("identity source contains an unterminated block comment".to_owned())
}

fn raw_string_end(
    source: &str,
    start: usize,
    byte_string: bool,
) -> Result<Option<(RustTokenKind, usize)>, String> {
    let bytes = source.as_bytes();
    let mut hashes = 0;
    let mut delimiter = start + 1;
    while bytes.get(delimiter) == Some(&b'#') {
        hashes += 1;
        delimiter += 1;
    }
    if bytes.get(delimiter) != Some(&b'"') {
        return Ok(None);
    }
    if hashes > 255 {
        return Err(ERR_TOO_MANY_RAW_HASHES.to_owned());
    }
    let mut index = delimiter + 1;
    let mut has_bare_cr = false;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let mut closing_hashes = 0;
            while closing_hashes <= hashes && bytes.get(index + 1 + closing_hashes) == Some(&b'#') {
                closing_hashes += 1;
            }
            if closing_hashes == hashes {
                if has_bare_cr {
                    return Err(ERR_BARE_CR_RAW.to_owned());
                }
                let end = index + hashes + 1;
                reject_literal_suffix(source, end)?;
                return Ok(Some((RustTokenKind::RawLiteral, end)));
            }
            if closing_hashes > hashes {
                return Err(ERR_TOO_MANY_RAW_HASHES.to_owned());
            }
        } else if bytes[index] == b'\r' && bytes.get(index + 1) != Some(&b'\n') {
            has_bare_cr = true;
        } else if byte_string && bytes[index] >= 0x80 {
            return Err(ERR_NON_ASCII_RAW_BYTE.to_owned());
        }
        index += 1;
    }
    Err(ERR_UNTERMINATED_RAW.to_owned())
}

fn normal_string_end(
    source: &str,
    start: usize,
    byte_string: bool,
) -> Result<(String, usize), String> {
    let bytes = source.as_bytes();
    let mut index = start + 1;
    while index < bytes.len() {
        if byte_string && bytes[index] >= 0x80 {
            return Err(ERR_MALFORMED_BYTE_STRING.to_owned());
        }
        match bytes[index] {
            b'\\' => index = string_escape_end(source, index, byte_string)?,
            b'"' => {
                reject_literal_suffix(source, index + 1)?;
                let value = if byte_string {
                    String::new()
                } else {
                    source[start + 1..index].to_owned()
                };
                return Ok((value, index + 1));
            }
            b'\r' if bytes.get(index + 1) != Some(&b'\n') => {
                return Err(ERR_BARE_CR_STRING.to_owned())
            }
            b'\n' | b'\r' => index += 1,
            _ => {
                index += source[index..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }
    Err(ERR_UNTERMINATED_STRING.to_owned())
}

fn string_escape_end(source: &str, slash: usize, byte_string: bool) -> Result<usize, String> {
    let bytes = source.as_bytes();
    let escaped = bytes
        .get(slash + 1)
        .copied()
        .ok_or_else(|| ERR_UNTERMINATED_STRING.to_owned())?;
    match escaped {
        b'\n' => Ok(skip_string_continuation(bytes, slash + 2)),
        b'\r' if bytes.get(slash + 2) == Some(&b'\n') => {
            Ok(skip_string_continuation(bytes, slash + 3))
        }
        b'\'' | b'"' | b'\\' | b'n' | b'r' | b't' | b'0' => Ok(slash + 2),
        b'x' => scan_hex_escape(bytes, slash, byte_string)
            .map_err(|_| invalid_string_escape(byte_string)),
        b'u' if !byte_string => {
            scan_unicode_escape(bytes, slash).map_err(|_| ERR_MALFORMED_STRING.to_owned())
        }
        _ => Err(invalid_string_escape(byte_string)),
    }
}

fn skip_string_continuation(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        index += 1;
    }
    index
}

fn invalid_string_escape(byte_string: bool) -> String {
    if byte_string {
        ERR_MALFORMED_BYTE_STRING.to_owned()
    } else {
        ERR_MALFORMED_STRING.to_owned()
    }
}

fn reject_literal_suffix(source: &str, end: usize) -> Result<(), String> {
    if source
        .get(end..)
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(is_rust_identifier_continue)
    {
        Err(ERR_INVALID_LITERAL_SUFFIX.to_owned())
    } else {
        Ok(())
    }
}

fn scan_hex_escape(bytes: &[u8], slash: usize, byte_string: bool) -> Result<usize, ()> {
    let first = slash + 2;
    let second = slash + 3;
    let Some(first_digit) = bytes.get(first).copied().and_then(hex_value) else {
        return Err(());
    };
    let Some(second_digit) = bytes.get(second).copied().and_then(hex_value) else {
        return Err(());
    };
    if !byte_string && u16::from(first_digit) * 16 + u16::from(second_digit) > 0x7f {
        return Err(());
    }
    Ok(slash + 4)
}

fn scan_unicode_escape(bytes: &[u8], slash: usize) -> Result<usize, ()> {
    if bytes.get(slash + 2) != Some(&b'{') {
        return Err(());
    }
    let mut index = slash + 3;
    let mut digits = 0;
    let mut value = 0_u32;
    while let Some(&byte) = bytes.get(index) {
        if let Some(digit) = hex_value(byte) {
            if digits == 6 {
                return Err(());
            }
            value = value * 16 + u32::from(digit);
            digits += 1;
        } else if byte == b'_' {
            if digits == 0 {
                return Err(());
            }
        } else if byte == b'}' {
            if digits == 0 || char::from_u32(value).is_none() {
                return Err(());
            }
            return Ok(index + 1);
        } else {
            return Err(());
        }
        index += 1;
    }
    Err(())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn looks_like_char_literal(source: &str, start: usize) -> bool {
    let bytes = source.as_bytes();
    if bytes.get(start + 1) == Some(&b'\\') || bytes.get(start + 1) == Some(&b'\'') {
        return true;
    }
    let Some(character) = source.get(start + 1..).and_then(|rest| rest.chars().next()) else {
        return false;
    };
    let mut index = start + 1 + character.len_utf8();
    if bytes.get(index) == Some(&b'\'') {
        return true;
    }
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            return true;
        }
        if bytes[index].is_ascii_whitespace() || b"{}[]();,:=&|<>+-*/!".contains(&bytes[index]) {
            return false;
        }
        let Some(next) = source[index..].chars().next() else {
            return false;
        };
        index += next.len_utf8();
    }
    false
}

fn char_literal_candidate<M: LexerMetricsSink>(
    source: &str,
    start: usize,
    previous_token: Option<&RustToken>,
    context: &RustLexicalContext,
    metrics: &mut M,
) -> bool {
    let expected = char_literal_expected_after(previous_token);
    if let Some(end) =
        lifetime_end(source, start).filter(|end| source.as_bytes().get(*end) != Some(&b'\''))
    {
        if context.lifetime_position(previous_token, source, end, metrics) {
            return false;
        }
        // Outside a type/macro/where context, a lifetime-shaped apostrophe is
        // in an expression position and must go through the character
        // scanner. This keeps malformed `'a` from becoming a fail-open token.
        return expected || context.expression_position();
    }
    looks_like_char_literal(source, start)
}

fn lifetime_end(source: &str, start: usize) -> Option<usize> {
    rust_identifier_end(source, start.checked_add(1)?)
}

fn char_literal_expected_after(previous_token: Option<&RustToken>) -> bool {
    previous_token.is_some_and(|token| {
        matches!(
            token.kind,
            RustTokenKind::Punctuation('=' | ',' | '(' | '[')
        )
    })
}

fn char_literal_end(source: &str, start: usize) -> Result<usize, String> {
    let bytes = source.as_bytes();
    let index = start + 1;
    let Some(&byte) = bytes.get(index) else {
        return Err(ERR_UNTERMINATED_CHARACTER.to_owned());
    };
    let content_end = if byte == b'\\' {
        character_escape_end(source, index)?
    } else if byte == b'\'' {
        return Err(ERR_EMPTY_CHARACTER.to_owned());
    } else if byte == b'\n' || byte == b'\r' {
        return Err(ERR_UNTERMINATED_CHARACTER.to_owned());
    } else if byte == b'\t' {
        return Err(ERR_MALFORMED_CHARACTER.to_owned());
    } else {
        let Some(character) = source.get(index..).and_then(|rest| rest.chars().next()) else {
            return Err(ERR_MALFORMED_CHARACTER.to_owned());
        };
        index + character.len_utf8()
    };
    match bytes.get(content_end) {
        Some(b'\'') => {
            reject_literal_suffix(source, content_end + 1)?;
            Ok(content_end + 1)
        }
        Some(b'\n' | b'\r') | None => Err(ERR_UNTERMINATED_CHARACTER.to_owned()),
        Some(_) => Err(ERR_MALFORMED_CHARACTER.to_owned()),
    }
}

fn character_escape_end(source: &str, slash: usize) -> Result<usize, String> {
    let bytes = source.as_bytes();
    let Some(&escaped) = bytes.get(slash + 1) else {
        return Err(ERR_UNTERMINATED_CHARACTER.to_owned());
    };
    match escaped {
        b'\'' | b'"' | b'\\' | b'n' | b'r' | b't' | b'0' => Ok(slash + 2),
        b'x' => {
            scan_hex_escape(bytes, slash, false).map_err(|_| ERR_MALFORMED_CHARACTER.to_owned())
        }
        b'u' => scan_unicode_escape(bytes, slash).map_err(|_| ERR_MALFORMED_CHARACTER.to_owned()),
        _ => Err(ERR_MALFORMED_CHARACTER.to_owned()),
    }
}

fn byte_char_literal_end(source: &str, quote_start: usize) -> Result<usize, String> {
    let bytes = source.as_bytes();
    let index = quote_start + 1;
    let Some(&byte) = bytes.get(index) else {
        return Err(ERR_UNTERMINATED_BYTE_CHARACTER.to_owned());
    };
    let content_end = if byte == b'\\' {
        byte_character_escape_end(bytes, index)?
    } else if byte == b'\'' {
        return Err(ERR_EMPTY_BYTE_CHARACTER.to_owned());
    } else if byte == b'\n' || byte == b'\r' {
        return Err(ERR_UNTERMINATED_BYTE_CHARACTER.to_owned());
    } else if !byte.is_ascii() || byte == b'\t' {
        return Err(ERR_MALFORMED_BYTE_CHARACTER.to_owned());
    } else {
        index + 1
    };
    match bytes.get(content_end) {
        Some(b'\'') => {
            reject_literal_suffix(source, content_end + 1)?;
            Ok(content_end + 1)
        }
        Some(b'\n' | b'\r') | None => Err(ERR_UNTERMINATED_BYTE_CHARACTER.to_owned()),
        Some(_) => Err(ERR_MALFORMED_BYTE_CHARACTER.to_owned()),
    }
}

fn byte_character_escape_end(bytes: &[u8], slash: usize) -> Result<usize, String> {
    let Some(&escaped) = bytes.get(slash + 1) else {
        return Err(ERR_UNTERMINATED_BYTE_CHARACTER.to_owned());
    };
    match escaped {
        b'\'' | b'"' | b'\\' | b'n' | b'r' | b't' | b'0' => Ok(slash + 2),
        b'x' => {
            scan_hex_escape(bytes, slash, true).map_err(|_| ERR_MALFORMED_BYTE_CHARACTER.to_owned())
        }
        _ => Err(ERR_MALFORMED_BYTE_CHARACTER.to_owned()),
    }
}

fn rust_identifier_end(source: &str, start: usize) -> Option<usize> {
    let first = source.get(start..)?.chars().next()?;
    if !is_rust_identifier_start(first) {
        return None;
    }
    let mut end = start + first.len_utf8();
    for character in source.get(end..)?.chars() {
        if !is_rust_identifier_continue(character) {
            break;
        }
        end += character.len_utf8();
    }
    Some(end)
}

// Rust 1.97.1 uses Unicode 17.0.0. These sorted deltas make the standard
// alphabetic predicates match XID_Start and XID_Continue without a dependency.
const NON_XID_START_ALPHABETIC_RANGES: &[(u32, u32)] = &[
    (0x0345, 0x0345),
    (0x0363, 0x036f),
    (0x037a, 0x037a),
    (0x05b0, 0x05bd),
    (0x05bf, 0x05bf),
    (0x05c1, 0x05c2),
    (0x05c4, 0x05c5),
    (0x05c7, 0x05c7),
    (0x0610, 0x061a),
    (0x064b, 0x0657),
    (0x0659, 0x065f),
    (0x0670, 0x0670),
    (0x06d6, 0x06dc),
    (0x06e1, 0x06e4),
    (0x06e7, 0x06e8),
    (0x06ed, 0x06ed),
    (0x0711, 0x0711),
    (0x0730, 0x073f),
    (0x07a6, 0x07b0),
    (0x0816, 0x0817),
    (0x081b, 0x0823),
    (0x0825, 0x0827),
    (0x0829, 0x082c),
    (0x0897, 0x0897),
    (0x08d4, 0x08df),
    (0x08e3, 0x08e9),
    (0x08f0, 0x0903),
    (0x093a, 0x093b),
    (0x093e, 0x094c),
    (0x094e, 0x094f),
    (0x0955, 0x0957),
    (0x0962, 0x0963),
    (0x0981, 0x0983),
    (0x09be, 0x09c4),
    (0x09c7, 0x09c8),
    (0x09cb, 0x09cc),
    (0x09d7, 0x09d7),
    (0x09e2, 0x09e3),
    (0x0a01, 0x0a03),
    (0x0a3e, 0x0a42),
    (0x0a47, 0x0a48),
    (0x0a4b, 0x0a4c),
    (0x0a51, 0x0a51),
    (0x0a70, 0x0a71),
    (0x0a75, 0x0a75),
    (0x0a81, 0x0a83),
    (0x0abe, 0x0ac5),
    (0x0ac7, 0x0ac9),
    (0x0acb, 0x0acc),
    (0x0ae2, 0x0ae3),
    (0x0afa, 0x0afc),
    (0x0b01, 0x0b03),
    (0x0b3e, 0x0b44),
    (0x0b47, 0x0b48),
    (0x0b4b, 0x0b4c),
    (0x0b56, 0x0b57),
    (0x0b62, 0x0b63),
    (0x0b82, 0x0b82),
    (0x0bbe, 0x0bc2),
    (0x0bc6, 0x0bc8),
    (0x0bca, 0x0bcc),
    (0x0bd7, 0x0bd7),
    (0x0c00, 0x0c04),
    (0x0c3e, 0x0c44),
    (0x0c46, 0x0c48),
    (0x0c4a, 0x0c4c),
    (0x0c55, 0x0c56),
    (0x0c62, 0x0c63),
    (0x0c81, 0x0c83),
    (0x0cbe, 0x0cc4),
    (0x0cc6, 0x0cc8),
    (0x0cca, 0x0ccc),
    (0x0cd5, 0x0cd6),
    (0x0ce2, 0x0ce3),
    (0x0cf3, 0x0cf3),
    (0x0d00, 0x0d03),
    (0x0d3e, 0x0d44),
    (0x0d46, 0x0d48),
    (0x0d4a, 0x0d4c),
    (0x0d57, 0x0d57),
    (0x0d62, 0x0d63),
    (0x0d81, 0x0d83),
    (0x0dcf, 0x0dd4),
    (0x0dd6, 0x0dd6),
    (0x0dd8, 0x0ddf),
    (0x0df2, 0x0df3),
    (0x0e31, 0x0e31),
    (0x0e33, 0x0e3a),
    (0x0e4d, 0x0e4d),
    (0x0eb1, 0x0eb1),
    (0x0eb3, 0x0eb9),
    (0x0ebb, 0x0ebc),
    (0x0ecd, 0x0ecd),
    (0x0f71, 0x0f83),
    (0x0f8d, 0x0f97),
    (0x0f99, 0x0fbc),
    (0x102b, 0x1036),
    (0x1038, 0x1038),
    (0x103b, 0x103e),
    (0x1056, 0x1059),
    (0x105e, 0x1060),
    (0x1062, 0x1064),
    (0x1067, 0x106d),
    (0x1071, 0x1074),
    (0x1082, 0x108d),
    (0x108f, 0x108f),
    (0x109a, 0x109d),
    (0x1712, 0x1713),
    (0x1732, 0x1733),
    (0x1752, 0x1753),
    (0x1772, 0x1773),
    (0x17b6, 0x17c8),
    (0x18a9, 0x18a9),
    (0x1920, 0x192b),
    (0x1930, 0x1938),
    (0x1a17, 0x1a1b),
    (0x1a55, 0x1a5e),
    (0x1a61, 0x1a74),
    (0x1abf, 0x1ac0),
    (0x1acc, 0x1ace),
    (0x1b00, 0x1b04),
    (0x1b35, 0x1b43),
    (0x1b80, 0x1b82),
    (0x1ba1, 0x1ba9),
    (0x1bac, 0x1bad),
    (0x1be7, 0x1bf1),
    (0x1c24, 0x1c36),
    (0x1dd3, 0x1df4),
    (0x24b6, 0x24e9),
    (0x2de0, 0x2dff),
    (0x2e2f, 0x2e2f),
    (0xa674, 0xa67b),
    (0xa69e, 0xa69f),
    (0xa802, 0xa802),
    (0xa80b, 0xa80b),
    (0xa823, 0xa827),
    (0xa880, 0xa881),
    (0xa8b4, 0xa8c3),
    (0xa8c5, 0xa8c5),
    (0xa8ff, 0xa8ff),
    (0xa926, 0xa92a),
    (0xa947, 0xa952),
    (0xa980, 0xa983),
    (0xa9b4, 0xa9bf),
    (0xa9e5, 0xa9e5),
    (0xaa29, 0xaa36),
    (0xaa43, 0xaa43),
    (0xaa4c, 0xaa4d),
    (0xaa7b, 0xaa7d),
    (0xaab0, 0xaab0),
    (0xaab2, 0xaab4),
    (0xaab7, 0xaab8),
    (0xaabe, 0xaabe),
    (0xaaeb, 0xaaef),
    (0xaaf5, 0xaaf5),
    (0xabe3, 0xabea),
    (0xfb1e, 0xfb1e),
    (0xfc5e, 0xfc63),
    (0xfdfa, 0xfdfb),
    (0xfe70, 0xfe70),
    (0xfe72, 0xfe72),
    (0xfe74, 0xfe74),
    (0xfe76, 0xfe76),
    (0xfe78, 0xfe78),
    (0xfe7a, 0xfe7a),
    (0xfe7c, 0xfe7c),
    (0xfe7e, 0xfe7e),
    (0xff9e, 0xff9f),
    (0x10376, 0x1037a),
    (0x10a01, 0x10a03),
    (0x10a05, 0x10a06),
    (0x10a0c, 0x10a0f),
    (0x10d24, 0x10d27),
    (0x10d69, 0x10d69),
    (0x10eab, 0x10eac),
    (0x10efa, 0x10efc),
    (0x11000, 0x11002),
    (0x11038, 0x11045),
    (0x11073, 0x11074),
    (0x11080, 0x11082),
    (0x110b0, 0x110b8),
    (0x110c2, 0x110c2),
    (0x11100, 0x11102),
    (0x11127, 0x11132),
    (0x11145, 0x11146),
    (0x11180, 0x11182),
    (0x111b3, 0x111bf),
    (0x111ce, 0x111cf),
    (0x1122c, 0x11234),
    (0x11237, 0x11237),
    (0x1123e, 0x1123e),
    (0x11241, 0x11241),
    (0x112df, 0x112e8),
    (0x11300, 0x11303),
    (0x1133e, 0x11344),
    (0x11347, 0x11348),
    (0x1134b, 0x1134c),
    (0x11357, 0x11357),
    (0x11362, 0x11363),
    (0x113b8, 0x113c0),
    (0x113c2, 0x113c2),
    (0x113c5, 0x113c5),
    (0x113c7, 0x113ca),
    (0x113cc, 0x113cd),
    (0x11435, 0x11441),
    (0x11443, 0x11445),
    (0x114b0, 0x114c1),
    (0x115af, 0x115b5),
    (0x115b8, 0x115be),
    (0x115dc, 0x115dd),
    (0x11630, 0x1163e),
    (0x11640, 0x11640),
    (0x116ab, 0x116b5),
    (0x1171d, 0x1172a),
    (0x1182c, 0x11838),
    (0x11930, 0x11935),
    (0x11937, 0x11938),
    (0x1193b, 0x1193c),
    (0x11940, 0x11940),
    (0x11942, 0x11942),
    (0x119d1, 0x119d7),
    (0x119da, 0x119df),
    (0x119e4, 0x119e4),
    (0x11a01, 0x11a0a),
    (0x11a35, 0x11a39),
    (0x11a3b, 0x11a3e),
    (0x11a51, 0x11a5b),
    (0x11a8a, 0x11a97),
    (0x11b60, 0x11b67),
    (0x11c2f, 0x11c36),
    (0x11c38, 0x11c3e),
    (0x11c92, 0x11ca7),
    (0x11ca9, 0x11cb6),
    (0x11d31, 0x11d36),
    (0x11d3a, 0x11d3a),
    (0x11d3c, 0x11d3d),
    (0x11d3f, 0x11d41),
    (0x11d43, 0x11d43),
    (0x11d47, 0x11d47),
    (0x11d8a, 0x11d8e),
    (0x11d90, 0x11d91),
    (0x11d93, 0x11d96),
    (0x11ef3, 0x11ef6),
    (0x11f00, 0x11f01),
    (0x11f03, 0x11f03),
    (0x11f34, 0x11f3a),
    (0x11f3e, 0x11f40),
    (0x1611e, 0x1612e),
    (0x16f4f, 0x16f4f),
    (0x16f51, 0x16f87),
    (0x16f8f, 0x16f92),
    (0x16ff0, 0x16ff1),
    (0x1bc9e, 0x1bc9e),
    (0x1e000, 0x1e006),
    (0x1e008, 0x1e018),
    (0x1e01b, 0x1e021),
    (0x1e023, 0x1e024),
    (0x1e026, 0x1e02a),
    (0x1e08f, 0x1e08f),
    (0x1e6e3, 0x1e6e3),
    (0x1e6e6, 0x1e6e6),
    (0x1e6ee, 0x1e6ef),
    (0x1e6f5, 0x1e6f5),
    (0x1e947, 0x1e947),
    (0x1f130, 0x1f149),
    (0x1f150, 0x1f169),
    (0x1f170, 0x1f189),
];

const NON_XID_CONTINUE_ALPHANUMERIC_RANGES: &[(u32, u32)] = &[
    (0x00b2, 0x00b3),
    (0x00b9, 0x00b9),
    (0x00bc, 0x00be),
    (0x037a, 0x037a),
    (0x09f4, 0x09f9),
    (0x0b72, 0x0b77),
    (0x0bf0, 0x0bf2),
    (0x0c78, 0x0c7e),
    (0x0d58, 0x0d5e),
    (0x0d70, 0x0d78),
    (0x0f2a, 0x0f33),
    (0x1372, 0x137c),
    (0x17f0, 0x17f9),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2150, 0x215f),
    (0x2189, 0x2189),
    (0x2460, 0x249b),
    (0x24b6, 0x24ff),
    (0x2776, 0x2793),
    (0x2cfd, 0x2cfd),
    (0x2e2f, 0x2e2f),
    (0x3192, 0x3195),
    (0x3220, 0x3229),
    (0x3248, 0x324f),
    (0x3251, 0x325f),
    (0x3280, 0x3289),
    (0x32b1, 0x32bf),
    (0xa830, 0xa835),
    (0xfc5e, 0xfc63),
    (0xfdfa, 0xfdfb),
    (0xfe70, 0xfe70),
    (0xfe72, 0xfe72),
    (0xfe74, 0xfe74),
    (0xfe76, 0xfe76),
    (0xfe78, 0xfe78),
    (0xfe7a, 0xfe7a),
    (0xfe7c, 0xfe7c),
    (0xfe7e, 0xfe7e),
    (0x10107, 0x10133),
    (0x10175, 0x10178),
    (0x1018a, 0x1018b),
    (0x102e1, 0x102fb),
    (0x10320, 0x10323),
    (0x10858, 0x1085f),
    (0x10879, 0x1087f),
    (0x108a7, 0x108af),
    (0x108fb, 0x108ff),
    (0x10916, 0x1091b),
    (0x109bc, 0x109bd),
    (0x109c0, 0x109cf),
    (0x109d2, 0x109ff),
    (0x10a40, 0x10a48),
    (0x10a7d, 0x10a7e),
    (0x10a9d, 0x10a9f),
    (0x10aeb, 0x10aef),
    (0x10b58, 0x10b5f),
    (0x10b78, 0x10b7f),
    (0x10ba9, 0x10baf),
    (0x10cfa, 0x10cff),
    (0x10e60, 0x10e7e),
    (0x10f1d, 0x10f26),
    (0x10f51, 0x10f54),
    (0x10fc5, 0x10fcb),
    (0x11052, 0x11065),
    (0x111e1, 0x111f4),
    (0x1173a, 0x1173b),
    (0x118ea, 0x118f2),
    (0x11c5a, 0x11c6c),
    (0x11fc0, 0x11fd4),
    (0x16b5b, 0x16b61),
    (0x16e80, 0x16e96),
    (0x1d2c0, 0x1d2d3),
    (0x1d2e0, 0x1d2f3),
    (0x1d360, 0x1d378),
    (0x1e8c7, 0x1e8cf),
    (0x1ec71, 0x1ecab),
    (0x1ecad, 0x1ecaf),
    (0x1ecb1, 0x1ecb4),
    (0x1ed01, 0x1ed2d),
    (0x1ed2f, 0x1ed3d),
    (0x1f100, 0x1f10c),
    (0x1f130, 0x1f149),
    (0x1f150, 0x1f169),
    (0x1f170, 0x1f189),
];

const ADDITIONAL_XID_CONTINUE_RANGES: &[(u32, u32)] = &[
    (0x00b7, 0x00b7),
    (0x0300, 0x0344),
    (0x0346, 0x0362),
    (0x0387, 0x0387),
    (0x0483, 0x0487),
    (0x0591, 0x05af),
    (0x0658, 0x0658),
    (0x06df, 0x06e0),
    (0x06ea, 0x06ec),
    (0x0740, 0x074a),
    (0x07eb, 0x07f3),
    (0x07fd, 0x07fd),
    (0x0818, 0x0819),
    (0x082d, 0x082d),
    (0x0859, 0x085b),
    (0x0898, 0x089f),
    (0x08ca, 0x08d3),
    (0x08e0, 0x08e1),
    (0x08ea, 0x08ef),
    (0x093c, 0x093c),
    (0x094d, 0x094d),
    (0x0951, 0x0954),
    (0x09bc, 0x09bc),
    (0x09cd, 0x09cd),
    (0x09fe, 0x09fe),
    (0x0a3c, 0x0a3c),
    (0x0a4d, 0x0a4d),
    (0x0abc, 0x0abc),
    (0x0acd, 0x0acd),
    (0x0afd, 0x0aff),
    (0x0b3c, 0x0b3c),
    (0x0b4d, 0x0b4d),
    (0x0b55, 0x0b55),
    (0x0bcd, 0x0bcd),
    (0x0c3c, 0x0c3c),
    (0x0c4d, 0x0c4d),
    (0x0cbc, 0x0cbc),
    (0x0ccd, 0x0ccd),
    (0x0d3b, 0x0d3c),
    (0x0d4d, 0x0d4d),
    (0x0dca, 0x0dca),
    (0x0e47, 0x0e4c),
    (0x0e4e, 0x0e4e),
    (0x0eba, 0x0eba),
    (0x0ec8, 0x0ecc),
    (0x0ece, 0x0ece),
    (0x0f18, 0x0f19),
    (0x0f35, 0x0f35),
    (0x0f37, 0x0f37),
    (0x0f39, 0x0f39),
    (0x0f3e, 0x0f3f),
    (0x0f84, 0x0f84),
    (0x0f86, 0x0f87),
    (0x0fc6, 0x0fc6),
    (0x1037, 0x1037),
    (0x1039, 0x103a),
    (0x135d, 0x135f),
    (0x1714, 0x1715),
    (0x1734, 0x1734),
    (0x17b4, 0x17b5),
    (0x17c9, 0x17d3),
    (0x17dd, 0x17dd),
    (0x180b, 0x180d),
    (0x180f, 0x180f),
    (0x1939, 0x193b),
    (0x1a60, 0x1a60),
    (0x1a75, 0x1a7c),
    (0x1a7f, 0x1a7f),
    (0x1ab0, 0x1abd),
    (0x1ac1, 0x1acb),
    (0x1acf, 0x1add),
    (0x1ae0, 0x1aeb),
    (0x1b34, 0x1b34),
    (0x1b44, 0x1b44),
    (0x1b6b, 0x1b73),
    (0x1baa, 0x1bab),
    (0x1be6, 0x1be6),
    (0x1bf2, 0x1bf3),
    (0x1c37, 0x1c37),
    (0x1cd0, 0x1cd2),
    (0x1cd4, 0x1ce8),
    (0x1ced, 0x1ced),
    (0x1cf4, 0x1cf4),
    (0x1cf7, 0x1cf9),
    (0x1dc0, 0x1dd2),
    (0x1df5, 0x1dff),
    (0x200c, 0x200d),
    (0x203f, 0x2040),
    (0x2054, 0x2054),
    (0x20d0, 0x20dc),
    (0x20e1, 0x20e1),
    (0x20e5, 0x20f0),
    (0x2118, 0x2118),
    (0x212e, 0x212e),
    (0x2cef, 0x2cf1),
    (0x2d7f, 0x2d7f),
    (0x302a, 0x302f),
    (0x3099, 0x309a),
    (0x30fb, 0x30fb),
    (0xa66f, 0xa66f),
    (0xa67c, 0xa67d),
    (0xa6f0, 0xa6f1),
    (0xa806, 0xa806),
    (0xa82c, 0xa82c),
    (0xa8c4, 0xa8c4),
    (0xa8e0, 0xa8f1),
    (0xa92b, 0xa92d),
    (0xa953, 0xa953),
    (0xa9b3, 0xa9b3),
    (0xa9c0, 0xa9c0),
    (0xaabf, 0xaabf),
    (0xaac1, 0xaac1),
    (0xaaf6, 0xaaf6),
    (0xabec, 0xabed),
    (0xfe00, 0xfe0f),
    (0xfe20, 0xfe2f),
    (0xfe33, 0xfe34),
    (0xfe4d, 0xfe4f),
    (0xff3f, 0xff3f),
    (0xff65, 0xff65),
    (0x101fd, 0x101fd),
    (0x102e0, 0x102e0),
    (0x10a38, 0x10a3a),
    (0x10a3f, 0x10a3f),
    (0x10ae5, 0x10ae6),
    (0x10d6a, 0x10d6d),
    (0x10efd, 0x10eff),
    (0x10f46, 0x10f50),
    (0x10f82, 0x10f85),
    (0x11046, 0x11046),
    (0x11070, 0x11070),
    (0x1107f, 0x1107f),
    (0x110b9, 0x110ba),
    (0x11133, 0x11134),
    (0x11173, 0x11173),
    (0x111c0, 0x111c0),
    (0x111c9, 0x111cc),
    (0x11235, 0x11236),
    (0x112e9, 0x112ea),
    (0x1133b, 0x1133c),
    (0x1134d, 0x1134d),
    (0x11366, 0x1136c),
    (0x11370, 0x11374),
    (0x113ce, 0x113d0),
    (0x113d2, 0x113d2),
    (0x113e1, 0x113e2),
    (0x11442, 0x11442),
    (0x11446, 0x11446),
    (0x1145e, 0x1145e),
    (0x114c2, 0x114c3),
    (0x115bf, 0x115c0),
    (0x1163f, 0x1163f),
    (0x116b6, 0x116b7),
    (0x1172b, 0x1172b),
    (0x11839, 0x1183a),
    (0x1193d, 0x1193e),
    (0x11943, 0x11943),
    (0x119e0, 0x119e0),
    (0x11a33, 0x11a34),
    (0x11a47, 0x11a47),
    (0x11a98, 0x11a99),
    (0x11c3f, 0x11c3f),
    (0x11d42, 0x11d42),
    (0x11d44, 0x11d45),
    (0x11d97, 0x11d97),
    (0x11f41, 0x11f42),
    (0x11f5a, 0x11f5a),
    (0x13440, 0x13440),
    (0x13447, 0x13455),
    (0x1612f, 0x1612f),
    (0x16af0, 0x16af4),
    (0x16b30, 0x16b36),
    (0x16fe4, 0x16fe4),
    (0x1bc9d, 0x1bc9d),
    (0x1cf00, 0x1cf2d),
    (0x1cf30, 0x1cf46),
    (0x1d165, 0x1d169),
    (0x1d16d, 0x1d172),
    (0x1d17b, 0x1d182),
    (0x1d185, 0x1d18b),
    (0x1d1aa, 0x1d1ad),
    (0x1d242, 0x1d244),
    (0x1da00, 0x1da36),
    (0x1da3b, 0x1da6c),
    (0x1da75, 0x1da75),
    (0x1da84, 0x1da84),
    (0x1da9b, 0x1da9f),
    (0x1daa1, 0x1daaf),
    (0x1e130, 0x1e136),
    (0x1e2ae, 0x1e2ae),
    (0x1e2ec, 0x1e2ef),
    (0x1e4ec, 0x1e4ef),
    (0x1e5ee, 0x1e5ef),
    (0x1e8d0, 0x1e8d6),
    (0x1e944, 0x1e946),
    (0x1e948, 0x1e94a),
    (0xe0100, 0xe01ef),
];

fn is_rust_identifier_start(character: char) -> bool {
    character == '_'
        || ((character.is_alphabetic()
            || matches!(character, '\u{1885}' | '\u{1886}' | '\u{2118}' | '\u{212e}'))
            && !rust_identifier_range_contains(NON_XID_START_ALPHABETIC_RANGES, character))
}

fn is_rust_identifier_continue(character: char) -> bool {
    let standard_candidate = character == '_' || character.is_alphanumeric();
    (standard_candidate
        && !rust_identifier_range_contains(NON_XID_CONTINUE_ALPHANUMERIC_RANGES, character))
        || rust_identifier_range_contains(ADDITIONAL_XID_CONTINUE_RANGES, character)
}

fn rust_identifier_range_contains(ranges: &[(u32, u32)], character: char) -> bool {
    let code_point = u32::from(character);
    let mut low = 0;
    let mut high = ranges.len();
    while low < high {
        let middle = low + (high - low) / 2;
        let (start, end) = ranges[middle];
        if code_point < start {
            high = middle;
        } else if code_point > end {
            low = middle + 1;
        } else {
            return true;
        }
    }
    false
}

fn is_reserved_raw_identifier(identifier: &str) -> bool {
    matches!(identifier, "_" | "crate" | "self" | "Self" | "super")
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<CliOptions>, String> {
    let mut suite = Suite::Smoke;
    let mut format = OutputFormat::Human;
    let mut seed = None;
    let mut samples = None;
    let mut sample_time = None;
    let mut warmup_time = None;
    let mut batches = None;
    let mut logical_time_ms = R17_DETERMINISTIC_SMOKE_LOGICAL_TIME_MS;
    let mut validate_artifact = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--suite" => {
                let value = next_value(&mut args, "--suite")?;
                suite = match value.as_str() {
                    "smoke" => Suite::Smoke,
                    "datapath" => Suite::Datapath,
                    "deterministic-smoke" => Suite::DeterministicSmoke,
                    _ => return Err(format!("unknown suite {value:?}")),
                };
            }
            "--format" => {
                let value = next_value(&mut args, "--format")?;
                format = match value.as_str() {
                    "human" => OutputFormat::Human,
                    "jsonl" => OutputFormat::JsonLines,
                    "both" => OutputFormat::Both,
                    _ => return Err(format!("unknown output format {value:?}")),
                };
            }
            "--seed" => {
                seed = Some(parse_u64(next_value(&mut args, "--seed")?, "--seed")?);
            }
            "--samples" => {
                samples = Some(parse_value(
                    next_value(&mut args, "--samples")?,
                    "--samples",
                )?);
            }
            "--sample-ms" => {
                let millis = parse_value(next_value(&mut args, "--sample-ms")?, "--sample-ms")?;
                sample_time = Some(Duration::from_millis(millis));
            }
            "--warmup-ms" => {
                let millis = parse_value(next_value(&mut args, "--warmup-ms")?, "--warmup-ms")?;
                warmup_time = Some(Duration::from_millis(millis));
            }
            "--batches" => {
                let value = next_value(&mut args, "--batches")?;
                batches = Some(
                    value
                        .split(',')
                        .map(|part| parse_value(part.to_owned(), "--batches"))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            "--logical-time-ms" => {
                logical_time_ms = parse_u64(
                    next_value(&mut args, "--logical-time-ms")?,
                    "--logical-time-ms",
                )?;
            }
            "--validate-artifact" => {
                validate_artifact = Some(next_value(&mut args, "--validate-artifact")?);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(None);
            }
            _ => return Err(format!("unknown argument {argument:?}; try --help")),
        }
    }
    let mut config = match suite {
        Suite::Smoke => RunConfig::smoke(),
        Suite::Datapath => RunConfig::datapath(),
        Suite::DeterministicSmoke => RunConfig::smoke(),
    };
    config.suite = suite;
    config.seed = seed.unwrap_or(config.seed);
    config.samples = samples.unwrap_or(config.samples);
    config.sample_time = sample_time.unwrap_or(config.sample_time);
    config.warmup_time = warmup_time.unwrap_or(config.warmup_time);
    config.batches = batches.unwrap_or(config.batches);
    Ok(Some(CliOptions {
        config,
        format,
        logical_time_ms,
        validate_artifact,
    }))
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_value<T: std::str::FromStr>(value: String, option: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{option} has invalid value {value:?}"))
}

fn parse_u64(value: String, option: &str) -> Result<u64, String> {
    let parsed = value
        .strip_prefix("0x")
        .map_or_else(|| value.parse::<u64>(), |hex| u64::from_str_radix(hex, 16));
    parsed.map_err(|_| format!("{option} has invalid value {value:?}"))
}

fn suite_name(suite: Suite) -> &'static str {
    match suite {
        Suite::Smoke => "smoke",
        Suite::Datapath => "datapath",
        Suite::DeterministicSmoke => "deterministic-smoke",
    }
}

fn print_help() {
    println!(
        "\
NIC-free ruster-core benchmark foundation

Usage: ruster-bench [OPTIONS]
  --suite smoke|datapath|deterministic-smoke
  --format human|jsonl|both
  --seed U64
  --samples N
  --sample-ms N
  --warmup-ms N
  --batches N[,N...]
  --logical-time-ms N
  --validate-artifact PATH

Timed regions exclude fixture reset and batch acquisition. Any successful
allocation observed inside a timed region fails the run. The deterministic
smoke suite emits canonical JSONL and does not use wall-clock timing."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_cli_values_override_suite_defaults_deterministically() {
        let arguments = [
            "--suite",
            "datapath",
            "--samples",
            "3",
            "--batches",
            "1,64",
            "--format",
            "jsonl",
        ]
        .into_iter()
        .map(str::to_owned);
        let options = parse_args(arguments).unwrap().unwrap();
        let config = options.config;
        assert_eq!(config.suite, Suite::Datapath);
        assert_eq!(config.samples, 3);
        assert_eq!(config.batches, [1, 64]);
        assert_eq!(options.format, OutputFormat::JsonLines);
    }

    #[test]
    fn option_order_does_not_change_suite_overrides() {
        let arguments = ["--samples", "3", "--suite", "datapath"]
            .into_iter()
            .map(str::to_owned);
        let options = parse_args(arguments).unwrap().unwrap();
        assert_eq!(options.config.suite, Suite::Datapath);
        assert_eq!(options.config.samples, 3);
    }

    #[test]
    fn deterministic_smoke_cli_accepts_fixed_hex_seed_and_artifact_validation() {
        let arguments = [
            "--suite",
            "deterministic-smoke",
            "--format",
            "jsonl",
            "--seed",
            "0x5eed020000000001",
            "--logical-time-ms",
            "1000",
            "--validate-artifact",
            "smoke.jsonl",
        ]
        .into_iter()
        .map(str::to_owned);
        let options = parse_args(arguments).unwrap().unwrap();
        assert_eq!(options.config.suite, Suite::DeterministicSmoke);
        assert_eq!(options.config.seed, 0x5eed_0200_0000_0001);
        assert_eq!(options.logical_time_ms, 1_000);
        assert_eq!(options.validate_artifact.as_deref(), Some("smoke.jsonl"));
    }

    #[test]
    fn deterministic_smoke_rejects_noncanonical_output_formats() {
        assert_eq!(
            deterministic_format_error(OutputFormat::Human),
            Some("deterministic-smoke requires --format jsonl; canonical output is JSONL")
        );
        assert_eq!(deterministic_format_error(OutputFormat::JsonLines), None);
        assert_eq!(
            deterministic_format_error(OutputFormat::Both),
            Some("deterministic-smoke requires --format jsonl; canonical output is JSONL")
        );
    }

    #[test]
    fn r17_f05_identity_lexer_fail_closes_literal_and_comment_eof() {
        let valid = concat!(
            "const raw: &str = r\"raw /* text */ // text\";\n",
            "const raw_hash: &str = r#\"raw \" quote\"#;\n",
            "const raw_byte_hash: &[u8] = br##\"raw # \"##;\n",
            "const raw_lf: &str = r\"raw\nliteral\";\n",
            "const raw_crlf: &str = r\"raw\r\nliteral\";\n",
            "const raw_byte_lf: &[u8] = br\"raw\nliteral\";\n",
            "const raw_byte_crlf: &[u8] = br\"raw\r\nliteral\";\n",
            "const normal: &str = \"escaped quote: \\\"\";\n",
            "const character_plain: char = 'x';\n",
            "const character_tab: char = '\\t';\n",
            "const character: char = '\\n';\n",
            "const character_unicode: char = '\\u{03bb}';\n",
            "const character_hex: char = '\\x7f';\n",
            "const byte_character: u8 = b'x';\n",
            r#"const byte_double_quote: u8 = b'\"';"#,
            "\n",
            r#"const byte_quote: u8 = b'\'';"#,
            "\n",
            r#"const byte_backslash: u8 = b'\\';"#,
            "\n",
            r#"const byte_newline: u8 = b'\n';"#,
            "\n",
            r#"const byte_carriage_return: u8 = b'\r';"#,
            "\n",
            r#"const byte_tab: u8 = b'\t';"#,
            "\n",
            r#"const byte_nul: u8 = b'\0';"#,
            "\n",
            r#"const byte_hex: u8 = b'\x7f';"#,
            "\n",
            "/* outer /* nested */ comment */\n",
        );
        assert!(tokenize_rust_source(valid).is_ok());
        assert_eq!(
            tokenize_rust_source("b'x'").unwrap(),
            vec![RustToken {
                kind: RustTokenKind::RawLiteral,
                start: 0,
            }]
        );

        for malformed in [
            "const raw: &str = r\"unterminated\n",
            "const raw_hash: &str = r###\"unterminated\n",
            "const raw_byte: &[u8] = br\"unterminated\n",
            "const raw_byte_hash: &[u8] = br##\"unterminated\n",
            "const normal: &str = \"unterminated\n",
            "const character: char = 'x\n",
            "const byte_character: u8 = b'x;",
            r#"const byte_escape: u8 = b'\x7;"#,
            r#"const byte_unicode: u8 = b'\u{03bb}';"#,
            r#"const byte_multiple: u8 = b'ab';"#,
            "const byte_non_ascii: u8 = b'λ';",
            "/* unterminated nested /* comment\n",
        ] {
            let error = tokenize_rust_source(malformed).unwrap_err();
            assert!(
                !error.contains(malformed),
                "lexer error must not echo source content"
            );
        }
    }

    #[test]
    fn r17_f07_large_lifetime_fixture_has_linear_context_visits() {
        let source = large_lifetime_identity_fixture();
        assert_eq!(source.len(), 63_536);
        assert_eq!(
            source
                .windows(3)
                .filter(|window| **window == b"'a,"[..])
                .count(),
            21_000
        );

        let source_text = std::str::from_utf8(&source).unwrap();
        let mut metrics = CountingLexerMetrics::default();
        let tokens = tokenize_rust_source_inner(source_text, &mut metrics).unwrap();
        assert_eq!(metrics.token_observations, tokens.len());
        assert_eq!(metrics.context_queries, 21_000);
        let linear_bound = tokens.len().saturating_mul(2).saturating_add(1);
        assert!(
            metrics
                .token_observations
                .saturating_add(metrics.context_queries)
                <= linear_bound,
            "context work exceeded the linear bound: metrics={metrics:?}, tokens={}",
            tokens.len()
        );

        let (compiled, typed) = parse_identity_source(&source).unwrap();
        assert_eq!(compiled, ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX);
        assert_eq!(typed, ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX);
    }

    #[test]
    fn r17_f07_forward_context_preserves_operator_macro_and_where_lifetimes() {
        for fixture in [
            b"macro_rules! valid_le { (1 <= 2, 'a) => {}; }".as_slice(),
            b"macro_rules! valid_ge { (1 >= 2, 'a) => {}; }".as_slice(),
            b"macro_rules! valid_shl { (1 << 2, 'a) => {}; }".as_slice(),
            b"macro_rules! valid_shr { (1 >> 2, 'a) => {}; }".as_slice(),
            b"macro_rules! valid_generic { (< 'a, 'b >) => {}; }".as_slice(),
            b"fn valid_where<'a, 'b>(a: &'a u8, b: &'b u8) where 'a: 'b { let _ = (a, b); }"
                .as_slice(),
            b"fn valid_assoc<'a, T>(a: &'a T) where T: Iterator<Item = &'a T>, 'a: 'a { let _ = a; }"
                .as_slice(),
            b"fn valid_nested<'a>() { let _: Option<Result<&'a u8, u8>> = None; }".as_slice(),
            b"fn valid_comparison(a: u8, b: u8) { let _ = a < b; }".as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        assert_identity_fixture_rejected(b"const INVALID_CHAR_OPERATOR: char = 'a<=;");
    }

    #[test]
    fn task80_six_strict_identity_lexer_regressions() {
        assert_identity_fixture_rejected(b"const INVALID_CMP: bool = (1 < 2, 'a);");
        assert_identity_fixture_accepts(
            b"fn VALID_LABEL_COMMA() { let _ = (1u8, 'lbl: loop { break 'lbl; }); }",
        );
        assert_identity_fixture_accepts(b"macro_rules! VALID_MACRO_START { ('a) => {}; }");
        assert_identity_fixture_rejected(
            b"fn VALID_WHERE<'a>() where 'a: 'a {} const INVALID_AFTER_WHERE: bool = 1, 'a;",
        );
        assert_identity_fixture_rejected(
            b"fn r#where() {} const INVALID_AFTER_RAW_IDENTIFIER: bool = 1, 'a;",
        );
        assert_identity_fixture_rejected(b"const CASE_RAW_ONE_SHORT_BODY: &str = r#\"A\"#B;");
    }

    #[test]
    fn r17_additional_five_context_and_unicode_regressions() {
        for fixture in [
            b"struct S<'a>(&'a ()); type A<'a> = S<'a>;".as_slice(),
            b"struct S<'a>(&'a ()); trait T<'a> { type A; } impl<'a> T<'a> for () { type A = S<'a>; }"
                .as_slice(),
            b"struct S<'a>(&'a ()); fn f<'a>() { let _: ((Option<S<'a>>,), [Option<S<'a>>; 1]) = ((None,), [None]); }"
                .as_slice(),
            b"struct S<'a>(&'a ()); struct R<'a> { field: (Option<S<'a>>,) }".as_slice(),
            b"struct S<'a>(&'a ()); fn f<'a>() { let _ = core::mem::size_of::<S<'a>>(); }"
                .as_slice(),
            b"struct S<'a>(&'a ()); impl<'a> S<'a> { fn f() {} } fn g<'a>() { S::<'a>::f(); }"
                .as_slice(),
            b"fn operators() { let _ = 1 < 2; let _ = 1 <= 2; let _ = 1 << 2; let _ = 2 > 1; let _ = 2 >= 1; let _ = 2 >> 1; }"
                .as_slice(),
            "fn r#λ() {} fn r#℘() {} fn r#℮() {} fn r#self́() {} fn r#self١() {} fn r#self‿() {} fn r#self·() {} fn r#selfְ() {} fn r#self҃() {} fn r#where() {}"
                .as_bytes(),
            br##"const RAW: &str = r#"A"#; const RAW_BYTE: &[u8] = br#"A"#;"##.as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        for raw_identifier in [
            "r#λ",
            "r#℘",
            "r#℮",
            "r#self́",
            "r#self١",
            "r#self‿",
            "r#self·",
            "r#selfְ",
            "r#self҃",
            "r#where",
        ] {
            assert_eq!(
                tokenize_rust_source(raw_identifier).unwrap(),
                vec![RustToken {
                    kind: RustTokenKind::Word(raw_identifier.to_owned()),
                    start: 0,
                }]
            );
        }

        for fixture in [
            b"static INVALID: bool = (1 < 2, 'a);".as_slice(),
            b"fn invalid() { let _ = (1 < 2, 'a); }".as_slice(),
            b"struct E { field: bool } fn invalid() { let _ = E { field: (1 < 2, 'a) }; }"
                .as_slice(),
            "const INVALID: &str = \"A\"λ;".as_bytes(),
            "const INVALID: &str = r\"A\"λ;".as_bytes(),
            "const INVALID: &[u8] = b\"A\"λ;".as_bytes(),
            "const INVALID: &[u8] = br\"A\"λ;".as_bytes(),
            "const INVALID: char = 'A'λ;".as_bytes(),
            "const INVALID: u8 = b'A'λ;".as_bytes(),
            b"fn r#self() {}".as_slice(),
            b"fn r#Self() {}".as_slice(),
            b"fn r#super() {}".as_slice(),
            b"fn r#crate() {}".as_slice(),
            b"fn r#_() {}".as_slice(),
            "fn r#ְ() {}".as_bytes(),
            "fn r#Ⓐ() {}".as_bytes(),
            "fn r#self²() {}".as_bytes(),
        ] {
            assert_identity_fixture_rejected(fixture);
        }
    }

    #[test]
    fn r17_residual_seven_context_and_suffix_regressions() {
        for fixture in [
            b"struct S<'a>(&'a ()); fn f<'a>() { let _ = core::mem::size_of:: <S<'a>>(); }"
                .as_slice(),
            b"struct S<'a>(&'a ()); fn f<'a>() { let _ = core::mem::size_of::/*x*/<S<'a>>(); }"
                .as_slice(),
            b"struct S<'a>(&'a ()); trait T { fn f(); } impl<'a> T for S<'a> { fn f() {} } fn q<'a>() { <S<'a> as T>::f(); }"
                .as_slice(),
            b"struct S<'a>(&'a ()); fn f<'a>() { let _ = |_: Option<S<'a>>| {}; }"
                .as_slice(),
            b"struct S<'a>(&'a ()); fn f<'a>() { let _ = |_: Option<S<'a>>| |_: Option<S<'a>>| {}; }"
                .as_slice(),
            b"struct S<'a>(&'a ()); enum E<'a> { Tuple(S<'a>), Record { field: S<'a> }, }"
                .as_slice(),
            b"struct S<'a>(&'a ()); type F<'a> = for<'b> fn(&'b S<'a>);".as_slice(),
            b"struct G<const N: usize>; type Good = G<{ 1 + 'a' as usize }>; type Array = [u8; 1 + 'a' as usize];"
                .as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        for fixture in [
            b"const INVALID: &str = \"A\"0;".as_slice(),
            b"const INVALID: &str = r\"A\"0;".as_slice(),
            b"const INVALID: &[u8] = b\"A\"0;".as_slice(),
            b"const INVALID: &[u8] = br\"A\"0;".as_slice(),
            b"const INVALID: char = 'A'0;".as_slice(),
            b"const INVALID: u8 = b'A'0;".as_slice(),
            "const INVALID: &str = \"A\"́;".as_bytes(),
            "const INVALID: &str = r\"A\"́;".as_bytes(),
            "const INVALID: &[u8] = b\"A\"́;".as_bytes(),
            "const INVALID: &[u8] = br\"A\"́;".as_bytes(),
            "const INVALID: char = 'A'́;".as_bytes(),
            "const INVALID: u8 = b'A'́;".as_bytes(),
            b"struct G<const N: usize>; type Bad = G<1 + 'a as usize>;".as_slice(),
            b"type Bad = [u8; 1 + 'a as usize];".as_slice(),
            b"fn invalid<'a>(a: bool, b: bool) { let _ = a || b: &'a u8; }".as_slice(),
        ] {
            assert_identity_fixture_rejected(fixture);
        }
    }

    #[test]
    fn r17_final_residual_context_regressions() {
        for fixture in [
            "fn valid_xid_labels() { 'á: loop { break 'á; } 'a‿: loop { break 'a‿; } 'a·: loop { break 'a·; } }".as_bytes(),
            b"fn valid_range_closure<'a>() { let _ = .. |_: &'a ()| (); }".as_slice(),
            b"struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid_range_qpath<'a>() { let _ = .. <S<'a> as T>::C; }".as_slice(),
            b"struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } fn valid_break_qpath<'a>() { let _: usize = 'lbl: loop { break 'lbl <S<'a> as T>::C; }; }".as_slice(),
            b"fn valid_nearby<'a>(value: &'a ()) { let _ = 'a'; 'lbl: loop { break 'lbl; } macro_rules! lifetime_token { ('a) => {}; } let _ = value; }".as_slice(),
            b"fn valid_label_after_block() { {} 'lbl: loop { break 'lbl; } }".as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        for fixture in [
            b"fn invalid_after_semicolon() { let _ = 1; 'a; }".as_slice(),
            b"fn invalid_after_empty_statements() { ;; 'a; }".as_slice(),
            b"type A = (); 'a;".as_slice(),
            b"fn invalid_after_block() { {}; 'a; }".as_slice(),
            b"fn invalid_after_item() { fn nested() {} 'a; }".as_slice(),
            b"struct S<'a>(&'a ()); trait T { const C: usize; } fn invalid_field_qpath<'a>(value: S<'a>) { let _ = value.<S<'a> as T>::C; }".as_slice(),
            b"struct S<'a>(&'a ()); fn invalid_triple_dot<'a>() { let _ = ... <S<'a>>; }".as_slice(),
        ] {
            assert_identity_fixture_rejected(fixture);
        }
    }

    #[test]
    fn r17_additional_seven_root_regressions() {
        for fixture in [
            b"use core::ops::{BitXor, Rem, Shl}; struct S<'a>(&'a ()); trait T { const C: usize; } impl<'a> T for S<'a> { const C: usize = 1; } struct L; impl Rem<usize> for L { type Output = (); fn rem(self, _: usize) {} } impl BitXor<usize> for L { type Output = (); fn bitxor(self, _: usize) {} } impl Shl<usize> for L { type Output = (); fn shl(self, _: usize) {} } fn valid_qpaths<'a>() { let _ = L % <S<'a> as T>::C; let _ = L ^ <S<'a> as T>::C; let _ = 0 < <S<'a> as T>::C; let _ = L << <S<'a> as T>::C; let _ = L<<<S<'a> as T>::C; for _ in <S<'a> as T>::C..2 {} }".as_slice(),
            b"use core::ops::{BitXor, Rem, Shl}; struct L; impl<F> Rem<F> for L { type Output = (); fn rem(self, _: F) {} } impl<F> BitXor<F> for L { type Output = (); fn bitxor(self, _: F) {} } impl<F> Shl<F> for L { type Output = (); fn shl(self, _: F) {} } impl<F> PartialEq<F> for L { fn eq(&self, _: &F) -> bool { false } } impl<F> PartialOrd<F> for L { fn partial_cmp(&self, _: &F) -> Option<core::cmp::Ordering> { None } } fn valid_closures<'a>() { let _ = L % |_: &'a ()| (); let _ = L ^ |_: &'a ()| (); let _ = L < |_: &'a ()| (); let _ = L << |_: &'a ()| (); }".as_slice(),
            b"fn valid_break_closure<'a>() { let _ = 'lbl: loop { break 'lbl |_: &'a ()| (); }; }".as_slice(),
            b"fn valid_numbers() { let _ = 1..2; let _ = 1e+2; let _ = 1e-2; let _ = 1e_2; let _ = 0b_1010_u8; let _ = 0o77i16; let _ = 0xffusize; let _ = 1.; let _ = 1.0f64; let _ = 1f32; }".as_slice(),
            br##"const VALID_C: &core::ffi::CStr = c"A"; const VALID_CR: &core::ffi::CStr = cr#"A"#;"##.as_slice(),
            b"macro_rules! valid_punctuation { ($x:expr) => { @ # ~ ? $x }; }".as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        for fixture in [
            b"const INVALID_SUFFIX: u8 = 1foo;".as_slice(),
            b"const INVALID_EXPONENT: f64 = 1e+;".as_slice(),
            b"const INVALID_RADIX: u8 = 0b102;".as_slice(),
            b"const INVALID_PREFIX: &str = foo\"A\";".as_slice(),
            b"const INVALID_CHAR_PREFIX: char = foo'a';".as_slice(),
            br##"const INVALID_RAW_PREFIX: &str = foo#"A"#;"##.as_slice(),
            "fn invalid() { let _ = ́; }".as_bytes(),
            "fn invalid() { let _ = 😀; }".as_bytes(),
            b"fn invalid() { let _ = `x`; }".as_slice(),
            b"fn invalid() { let _ = (0]; }".as_slice(),
            b"fn invalid() { let _ = [0); }".as_slice(),
            b"fn invalid() { let _ = (0; }".as_slice(),
        ] {
            assert_identity_fixture_rejected(fixture);
        }

        let mut nul = b"fn invalid() { let _ = ".to_vec();
        nul.push(0);
        nul.extend_from_slice(b"; }");
        assert_identity_fixture_rejected(&nul);
    }

    #[test]
    fn r17_f1_rejects_unclosed_expression_angle_at_statement_end() {
        assert_identity_fixture_rejected(b"const INVALID: bool = 0 < <1;");
    }

    #[test]
    fn r17_f2_rejects_unterminated_typed_closure_at_statement_end() {
        assert_identity_fixture_rejected(
            b"fn invalid<'a>() { let _ = 'lbl: loop { break 'lbl |_: &'a (); }; }",
        );
    }

    #[test]
    fn r17_f3_rejects_triple_dot_after_numeric_literal() {
        assert_identity_fixture_rejected(b"const INVALID: bool = 1...2;");
    }

    #[test]
    fn r17_f4_rejects_unclosed_generic_at_scope_pop() {
        assert_identity_fixture_rejected(b"struct S; fn invalid() { let _ = <S; }");
    }

    #[test]
    fn r17_preserves_valid_qpath_closure_range_generic_and_turbofish() {
        assert_identity_fixture_accepts(
            b"trait T { const C: usize; } struct S; impl T for S { const C: usize = 1; } fn valid() { let _ = 0 < <S as T>::C; let _ = |_: u8| (); let _ = 1..2; let _ = 1..=2; let _: Vec<Vec<u8>> = Vec::new(); let _: Vec<Vec<u8>>=Vec::new(); let _: Vec<u8> = Vec::<u8>::new(); } macro_rules! valid_tokens { (<;>) => {}; }",
        );
    }

    #[test]
    fn r17_f05_identity_parser_accepts_escaped_double_quote_byte_character() {
        let identity_source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs"));
        let source = format!(
            "{identity_source}\n{}",
            r#"const VALID_ESCAPED_DOUBLE_QUOTE: u8 = b'\"';"#
        );
        let (compiled, typed) = parse_identity_source(source.as_bytes()).unwrap();
        assert_eq!(compiled, ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX);
        assert_eq!(typed, ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX);
    }

    #[test]
    fn r17_f05_identity_parser_rejects_raw_tab_byte_character() {
        let mut source =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs")).to_vec();
        let fixture_prefix = b"\nconst RAW_TAB_BYTE: u8 = b'";
        source.extend_from_slice(fixture_prefix);
        let tab_offset = source.len();
        source.push(0x09);
        source.extend_from_slice(b"';\n");
        let fixture = &source[tab_offset - fixture_prefix.len()..];

        assert_eq!(
            &fixture[fixture_prefix.len() - 1..fixture_prefix.len() + 2],
            &[b'\'', 0x09, b'\'']
        );
        assert_eq!(
            &fixture[fixture_prefix.len()..fixture_prefix.len() + 1],
            &[0x09]
        );
        assert!(!fixture.windows(2).any(|window| window == *b"\\t"));

        let source_text = std::str::from_utf8(&source).unwrap();
        let lexer_error = tokenize_rust_source(source_text).unwrap_err();
        assert_eq!(
            lexer_error,
            "identity source contains a malformed byte character literal"
        );
        let parser_error = parse_identity_source(&source).unwrap_err();
        assert_eq!(parser_error, lexer_error);
    }

    #[test]
    fn r17_f05_identity_parser_rejects_raw_tab_character() {
        let mut source =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs")).to_vec();
        let fixture_prefix = b"\nconst RAW_TAB_CHAR: char = '";
        source.extend_from_slice(fixture_prefix);
        let tab_offset = source.len();
        source.push(0x09);
        source.extend_from_slice(b"';\n");
        let fixture = &source[tab_offset - fixture_prefix.len()..];

        assert_eq!(
            &fixture[fixture_prefix.len() - 1..fixture_prefix.len() + 2],
            &[b'\'', 0x09, b'\'']
        );
        assert_eq!(fixture[fixture_prefix.len()], 0x09);
        assert!(!fixture.windows(2).any(|window| window == *b"\\t"));

        let source_text = std::str::from_utf8(&source).unwrap();
        let lexer_error = tokenize_rust_source(source_text).unwrap_err();
        assert_eq!(
            lexer_error,
            "identity source contains a malformed character literal"
        );
        let parser_error = parse_identity_source(&source).unwrap_err();
        assert_eq!(parser_error, lexer_error);
    }

    #[test]
    fn r17_f05_identity_parser_rejects_bare_cr_in_raw_string_literals() {
        let fixtures = [
            (
                b"\nconst RAW_CR_STRING: &str = r\"A".as_slice(),
                b"B\";\n".as_slice(),
            ),
            (
                b"\nconst RAW_CR_BYTE_STRING: &[u8] = br\"A".as_slice(),
                b"B\";\n".as_slice(),
            ),
            (
                b"\nconst RAW_CR_HASH_STRING: &str = r#\"A".as_slice(),
                b"B\"#;\n".as_slice(),
            ),
            (
                b"\nconst RAW_CR_BYTE_HASH_STRING: &[u8] = br##\"A".as_slice(),
                b"B\"##;\n".as_slice(),
            ),
        ];

        for (fixture_prefix, fixture_suffix) in fixtures {
            let mut source =
                include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs")).to_vec();
            source.extend_from_slice(fixture_prefix);
            let cr_offset = source.len();
            source.push(0x0d);
            source.extend_from_slice(fixture_suffix);

            assert_eq!(source[cr_offset], 0x0d);
            assert!(!source[cr_offset..]
                .windows(2)
                .any(|window| window == *b"\\r"));

            let source_text = std::str::from_utf8(&source).unwrap();
            let lexer_error = tokenize_rust_source(source_text).unwrap_err();
            assert_eq!(
                lexer_error,
                "identity source contains a bare CR in a raw string literal"
            );
            let parser_error = parse_identity_source(&source).unwrap_err();
            assert_eq!(parser_error, lexer_error);
        }

        let mut unterminated =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs")).to_vec();
        unterminated.extend_from_slice(b"\nconst UNTERMINATED_RAW_CR: &str = r\"A");
        unterminated.push(0x0d);
        unterminated.extend_from_slice(b"B\n");
        assert_eq!(
            tokenize_rust_source(std::str::from_utf8(&unterminated).unwrap()),
            Err("identity source contains an unterminated raw string literal".to_owned())
        );
    }

    #[test]
    fn r17_f06_identity_parser_matches_char_escape_and_scalar_contract() {
        for fixture in [
            br#"const VALID_CHAR_ASCII: char = 'A';"#.as_slice(),
            r#"const VALID_CHAR_UTF8: char = 'λ';"#.as_bytes(),
            br#"const VALID_CHAR_QUOTE: char = '\'';"#.as_slice(),
            br#"const VALID_CHAR_BACKSLASH: char = '\\';"#.as_slice(),
            br#"const VALID_CHAR_TAB: char = '\t';"#.as_slice(),
            br#"const VALID_CHAR_NEWLINE: char = '\n';"#.as_slice(),
            br#"const VALID_CHAR_CR: char = '\r';"#.as_slice(),
            br#"const VALID_CHAR_NUL: char = '\0';"#.as_slice(),
            br#"const VALID_CHAR_HEX: char = '\x7f';"#.as_slice(),
            br#"const VALID_CHAR_UNDERSCORE: char = '\u{1_2}';"#.as_slice(),
            br#"const VALID_CHAR_UNDERSCORES: char = '\u{1___2___}';"#.as_slice(),
            br#"const VALID_CHAR_LEADING_ZERO: char = '\u{00001_2}';"#.as_slice(),
            br#"const VALID_CHAR_MAX: char = '\u{10ffff}';"#.as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        for fixture in [
            br#"const INVALID_CHAR_ESCAPE: char = '\q';"#.as_slice(),
            br#"const INVALID_CHAR_INCOMPLETE: char = '\x1';"#.as_slice(),
            br#"const INVALID_CHAR_HEX_RANGE: char = '\x80';"#.as_slice(),
            br#"const INVALID_CHAR_SURROGATE: char = '\u{d800}';"#.as_slice(),
            br#"const INVALID_CHAR_SCALAR: char = '\u{110000}';"#.as_slice(),
            br#"const INVALID_CHAR_EMPTY: char = '';"#.as_slice(),
            br#"const INVALID_CHAR_TWO_RAW: char = 'ab';"#.as_slice(),
            br#"const INVALID_CHAR_TWO_ESCAPES: char = '\n\t';"#.as_slice(),
            br#"const INVALID_CHAR_ESCAPE_AND_RAW: char = '\na';"#.as_slice(),
            br#"const INVALID_CHAR_UNTERMINATED: char = 'a"#.as_slice(),
        ] {
            assert_identity_fixture_rejected(fixture);
        }

        for (name, byte) in [
            (b"RAW_TAB_CHAR".as_slice(), 0x09),
            (b"RAW_LF_CHAR".as_slice(), 0x0a),
            (b"RAW_CR_CHAR".as_slice(), 0x0d),
        ] {
            let mut fixture = Vec::with_capacity(32);
            fixture.extend_from_slice(b"const ");
            fixture.extend_from_slice(name);
            fixture.extend_from_slice(b": char = '");
            fixture.push(byte);
            fixture.extend_from_slice(b"';");
            assert_identity_fixture_rejected(&fixture);
        }
    }

    #[test]
    fn r17_f06_identity_parser_matches_normal_and_byte_string_contract() {
        for fixture in [
            r##"const VALID_NORMAL_UTF8: &str = "AλB";"##.as_bytes(),
            br##"const VALID_NORMAL_ESCAPES: &str = "\n\r\t\0\'\"\\";"##.as_slice(),
            br##"const VALID_NORMAL_HEX_UNICODE: &str = "\x00\x7f\u{1_2}";"##.as_slice(),
            br##"const VALID_BYTE_ASCII: &[u8] = b"A";"##.as_slice(),
            br##"const VALID_BYTE_ESCAPES: &[u8] = b"\n\r\t\0\'\"\\\xff";"##.as_slice(),
        ] {
            assert_identity_fixture_accepts(fixture);
        }

        for fixture in [
            br##"const INVALID_NORMAL_ESCAPE: &str = "A\qB";"##.as_slice(),
            br##"const INVALID_NORMAL_INCOMPLETE: &str = "A\x1";"##.as_slice(),
            br##"const INVALID_NORMAL_SCALAR: &str = "\u{110000}";"##.as_slice(),
            br##"const INVALID_BYTE_ESCAPE: &[u8] = b"A\qB";"##.as_slice(),
            br##"const INVALID_BYTE_INCOMPLETE: &[u8] = b"A\x1";"##.as_slice(),
            br##"const INVALID_BYTE_UNICODE: &[u8] = b"\u{12}";"##.as_slice(),
            r##"const INVALID_BYTE_UTF8: &[u8] = b"AλB";"##.as_bytes(),
            r##"const INVALID_BYTE_UTF8_RAW_ESCAPE: &[u8] = b"λ";"##.as_bytes(),
        ] {
            assert_identity_fixture_rejected(fixture);
        }
    }

    #[test]
    fn r17_f06_identity_parser_accepts_lf_and_crlf_but_rejects_lone_cr() {
        for (prefix, suffix, body) in [
            (
                b"const VALID_NORMAL_LF: &str = \"A".as_slice(),
                b"B\";".as_slice(),
                vec![0x0a],
            ),
            (
                b"const VALID_NORMAL_CRLF: &str = \"A".as_slice(),
                b"B\";".as_slice(),
                vec![0x0d, 0x0a],
            ),
            (
                b"const VALID_BYTE_LF: &[u8] = b\"A".as_slice(),
                b"B\";".as_slice(),
                vec![0x0a],
            ),
            (
                b"const VALID_BYTE_CRLF: &[u8] = b\"A".as_slice(),
                b"B\";".as_slice(),
                vec![0x0d, 0x0a],
            ),
        ] {
            let fixture = literal_fixture(prefix, &body, suffix);
            assert_eq!(
                body.as_slice(),
                &fixture[prefix.len()..prefix.len() + body.len()]
            );
            assert_identity_fixture_accepts(&fixture);
        }

        let continuation = literal_fixture(
            b"const VALID_CONTINUATION: &str = \"A",
            &[b'\\', 0x0a, b' ', b'\t'],
            b"B\";",
        );
        assert_identity_fixture_accepts(&continuation);

        for (prefix, suffix) in [
            (
                b"const INVALID_NORMAL_LONE_CR: &str = \"A".as_slice(),
                b"B\";".as_slice(),
            ),
            (
                b"const INVALID_BYTE_LONE_CR: &[u8] = b\"A".as_slice(),
                b"B\";".as_slice(),
            ),
        ] {
            let fixture = literal_fixture(prefix, &[0x0d], suffix);
            assert_identity_fixture_rejected(&fixture);
        }
    }

    #[test]
    fn r17_f06_identity_parser_enforces_raw_hash_and_byte_domain_contract() {
        for (prefix, hashes, body, closing) in [
            (
                b"const VALID_RAW_0: &str = r".as_slice(),
                0,
                b"A".as_slice(),
                0,
            ),
            (
                b"const VALID_RAW_1: &str = r".as_slice(),
                1,
                b"A\"B".as_slice(),
                1,
            ),
            (
                b"const VALID_RAW_2: &str = r".as_slice(),
                2,
                b"A\"#B".as_slice(),
                2,
            ),
            (
                b"const VALID_RAW_255: &str = r".as_slice(),
                255,
                b"A".as_slice(),
                255,
            ),
            (
                b"const VALID_RAW_BYTE_255: &[u8] = br".as_slice(),
                255,
                b"A".as_slice(),
                255,
            ),
        ] {
            let fixture = raw_literal_fixture(prefix, hashes, body, closing);
            assert_identity_fixture_accepts(&fixture);
        }

        for body in [b"A\nB".as_slice(), b"A\r\nB".as_slice()] {
            let normal = raw_literal_fixture(b"const VALID_RAW_LINE: &str = r", 0, body, 0);
            let byte = raw_literal_fixture(b"const VALID_RAW_BYTE_LINE: &[u8] = br", 0, body, 0);
            assert_identity_fixture_accepts(&normal);
            assert_identity_fixture_accepts(&byte);
        }

        let embedded =
            raw_literal_fixture(b"const VALID_RAW_BYTE_EMBEDDED: &[u8] = br", 2, b"A\"#B", 2);
        assert_identity_fixture_accepts(&embedded);

        for fixture in [
            raw_literal_fixture(b"const INVALID_RAW_256: &str = r", 256, b"A", 256),
            raw_literal_fixture(b"const INVALID_RAW_EXTRA: &str = r", 1, b"A", 2),
            raw_literal_fixture(b"const INVALID_RAW_SHORT: &str = r", 2, b"A", 1),
            raw_literal_fixture(b"const INVALID_RAW_BYTE_256: &[u8] = br", 256, b"A", 256),
        ] {
            assert_identity_fixture_rejected(&fixture);
        }

        let non_ascii_raw_byte = raw_literal_fixture(
            b"const INVALID_RAW_BYTE_UTF8: &[u8] = br",
            0,
            "λ".as_bytes(),
            0,
        );
        assert_identity_fixture_rejected(&non_ascii_raw_byte);

        for (prefix, body) in [
            (
                b"const INVALID_RAW_CR: &str = r".as_slice(),
                b"A\rB".as_slice(),
            ),
            (
                b"const INVALID_RAW_BYTE_CR: &[u8] = br".as_slice(),
                b"A\rB".as_slice(),
            ),
        ] {
            let fixture = raw_literal_fixture(prefix, 0, body, 0);
            assert_identity_fixture_rejected(&fixture);
        }
    }

    fn literal_fixture(prefix: &[u8], body: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut fixture = Vec::with_capacity(prefix.len() + body.len() + suffix.len());
        fixture.extend_from_slice(prefix);
        fixture.extend_from_slice(body);
        fixture.extend_from_slice(suffix);
        fixture
    }

    fn large_lifetime_identity_fixture() -> Vec<u8> {
        let mut source = Vec::with_capacity(63_536);
        source.extend_from_slice(b"struct Sha256Digest([u8; 32]);\n");
        source.extend_from_slice(
            b"impl Sha256Digest { const fn from_bytes(value: [u8; 32]) -> Self { Self(value) } }\n",
        );
        source.extend_from_slice(b"pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([0x57, 0x37, 0x20, 0xcd, 0xe7, 0xbb, 0xd5, 0x22, 0xee, 0x8f, 0x54, 0x86, 0x8b, 0x41, 0xbb, 0xf2, 0x5e, 0xee, 0x9e, 0x3c, 0xb2, 0x27, 0xa9, 0x45, 0x53, 0xb5, 0x44, 0x11, 0xe1, 0x20, 0xde, 0x9d,]);\n");
        source.extend_from_slice(b"pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"573720cde7bbd522ee8f54868b41bbf25eee9e3cb227a94553b54411e120de9d\";\n");
        source.extend_from_slice(b"macro_rules! m { (< ");
        for _ in 0..21_000 {
            source.extend_from_slice(b"'a,");
        }
        source.extend_from_slice(b"> ) => {}; }\n");
        source
    }

    fn raw_literal_fixture(
        prefix: &[u8],
        opening_hashes: usize,
        body: &[u8],
        closing_hashes: usize,
    ) -> Vec<u8> {
        let mut fixture = Vec::with_capacity(
            prefix.len() + opening_hashes + 1 + body.len() + 1 + closing_hashes + 1,
        );
        fixture.extend_from_slice(prefix);
        fixture.extend(std::iter::repeat_n(b'#', opening_hashes));
        fixture.push(b'\"');
        fixture.extend_from_slice(body);
        fixture.push(b'\"');
        fixture.extend(std::iter::repeat_n(b'#', closing_hashes));
        fixture.push(b';');
        fixture
    }

    fn assert_identity_fixture_accepts(fixture: &[u8]) {
        let source = identity_source_with_fixture(fixture);
        let source_text = std::str::from_utf8(&source).expect("fixture must remain UTF-8");
        assert!(
            tokenize_rust_source(source_text).is_ok(),
            "lexer rejected a valid fixture"
        );
        assert!(
            parse_identity_source(&source).is_ok(),
            "identity parser rejected a valid fixture"
        );
    }

    fn assert_identity_fixture_rejected(fixture: &[u8]) {
        let source = identity_source_with_fixture(fixture);
        let source_text = std::str::from_utf8(&source).expect("fixture must remain UTF-8");
        let lexer_error = tokenize_rust_source(source_text).expect_err("fixture must be rejected");
        let parser_error = parse_identity_source(&source).expect_err("fixture must be rejected");
        assert_eq!(parser_error, lexer_error);
        assert!(lexer_error.starts_with("identity source contains "));
        assert!(!lexer_error.contains("INVALID_"));
    }

    fn identity_source_with_fixture(fixture: &[u8]) -> Vec<u8> {
        let mut source =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs")).to_vec();
        source.push(b'\n');
        source.extend_from_slice(fixture);
        source.push(b'\n');
        source
    }

    #[test]
    fn bounded_artifact_input_rejects_oversize_and_nonregular_files() {
        use std::fs::{create_dir, remove_dir, remove_file, write};

        let base = env::temp_dir().join(format!(
            "ruster-bench-r17-input-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let file_path = base.with_extension("jsonl");
        let directory_path = base.with_extension("directory");
        let oversized = vec![b'x'; R17_DETERMINISTIC_SMOKE_ARTIFACT_MAX_BYTES + 1];
        write(&file_path, oversized).unwrap();
        assert!(read_bounded_artifact(file_path.to_str().unwrap())
            .unwrap_err()
            .contains("byte limit"));
        remove_file(&file_path).unwrap();

        create_dir(&directory_path).unwrap();
        assert_eq!(
            read_bounded_artifact(directory_path.to_str().unwrap()),
            Err("deterministic smoke artifact input must be a regular file".to_owned())
        );
        remove_dir(&directory_path).unwrap();
    }

    #[test]
    fn bounded_artifact_input_rejects_invalid_utf8_after_bounded_read() {
        use std::fs::{remove_file, write};

        let path = env::temp_dir().join(format!(
            "ruster-bench-r17-invalid-utf8-{}",
            std::process::id()
        ));
        write(&path, [0xff, 0xfe]).unwrap();
        assert_eq!(
            read_bounded_artifact(path.to_str().unwrap()),
            Err("deterministic smoke artifact input is not valid UTF-8".to_owned())
        );
        remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_artifact_input_rejects_fifo_before_opening_it() {
        use std::fs::remove_file;
        use std::process::Command;

        let path = env::temp_dir().join(format!("ruster-bench-r17-fifo-{}", std::process::id()));
        let status = Command::new("mkfifo").arg(&path).status().unwrap();
        assert!(status.success());
        assert_eq!(
            read_bounded_artifact(path.to_str().unwrap()),
            Err("deterministic smoke artifact input must be a regular file".to_owned())
        );
        remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_artifact_input_rejects_symlink_without_following_it() {
        use std::fs::{remove_file, write};
        use std::os::unix::fs::symlink;

        let base = env::temp_dir().join(format!("ruster-bench-r17-symlink-{}", std::process::id()));
        let target = base.with_extension("target");
        let link = base.with_extension("link");
        write(&target, b"not-an-artifact").unwrap();
        symlink(&target, &link).unwrap();

        assert!(open_bounded_file(&link).is_err());
        assert_eq!(
            read_bounded_artifact(link.to_str().unwrap()),
            Err("deterministic smoke artifact input must be a regular file".to_owned())
        );

        remove_file(link).unwrap();
        remove_file(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_input_rejects_same_inode_same_length_mutations() {
        use std::fs::{remove_file, write};

        let base = env::temp_dir().join(format!(
            "ruster-bench-r17-mutation-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let rewrite_path = base.with_extension("rewrite");
        write(&rewrite_path, b"before").unwrap();
        let rewrite_result = read_bounded_file_inner(&rewrite_path, 64, || {
            let mut writer = OpenOptions::new().write(true).open(&rewrite_path).unwrap();
            writer.write_all(b"after!").unwrap();
            writer.flush().unwrap();
        });
        assert_eq!(rewrite_result, Err(BoundedFileError::Changed));
        remove_file(&rewrite_path).unwrap();

        let regrow_path = base.with_extension("regrow");
        write(&regrow_path, b"before").unwrap();
        let regrow_result = read_bounded_file_inner(&regrow_path, 64, || {
            let mut writer = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&regrow_path)
                .unwrap();
            writer.write_all(b"after!").unwrap();
            writer.flush().unwrap();
        });
        assert_eq!(regrow_result, Err(BoundedFileError::Changed));
        remove_file(regrow_path).unwrap();
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    #[test]
    fn bounded_open_is_nonblocking_for_fifo_replacement_race() {
        use std::fs::remove_file;
        use std::process::Command;

        let path =
            env::temp_dir().join(format!("ruster-bench-r17-open-fifo-{}", std::process::id()));
        let status = Command::new("mkfifo").arg(&path).status().unwrap();
        assert!(status.success());
        let file = open_bounded_file(&path).expect("nonblocking FIFO open");
        assert!(!file.metadata().unwrap().file_type().is_file());
        drop(file);
        remove_file(path).unwrap();
    }

    /// The shape of a real identity source, with `{extra}` spliced in.
    ///
    /// `parse_identity_source` needs both declarations to be present before
    /// the expansion question is even asked, so every case here keeps them.
    fn identity_source_with(extra: &str) -> Vec<u8> {
        format!(
            "{extra}pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
             pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n"
        )
        .into_bytes()
    }

    #[test]
    fn a_plain_identity_source_needs_no_expansion() {
        assert_eq!(
            identity_source_uses_expansion(&identity_source_with("")),
            Ok(false)
        );
    }

    #[test]
    fn an_include_makes_the_source_depend_on_expansion() {
        // `include!` can substitute whole items, so the lexical reading of the
        // file is not what the compiler sees.
        assert_eq!(
            identity_source_uses_expansion(&identity_source_with("include!(\"other.rs\");\n")),
            Ok(true)
        );
    }

    #[test]
    fn an_identity_value_that_comes_from_a_file_is_refused_before_the_expansion_question() {
        // `include_bytes!` and `include_str!` are not treated as expansion,
        // because they cannot substitute an item. Used as the *value* of an
        // identity they would still hide the real constant, so the check that
        // matters is that the lexical parser refuses them outright.
        for source in [
            "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = include_str!(\"x\");\n\
             pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n",
            "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
             pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = *include_bytes!(\"x\");\n",
        ] {
            assert!(
                parse_identity_source(source.as_bytes()).is_err(),
                "an identity read from another file must not parse: {source}"
            );
        }
    }

    #[test]
    fn a_cfg_on_the_second_identity_declaration_is_found_by_its_own_scan() {
        // Two guards can report a conditional identity: a top-level cfg seen
        // before any identity declaration, and a cfg attached to an identity
        // declaration. Only the second applies here, because the first
        // declaration has already been seen by the time this attribute
        // appears.
        let source = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      #[cfg(feature = \"x\")]\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n";
        assert_eq!(
            identity_source_uses_expansion(source.as_bytes()),
            Ok(true),
            "a cfg on the second identity declaration must be found"
        );
    }

    #[test]
    fn a_cfg_on_the_second_identity_declaration_is_found_behind_other_attributes() {
        // The scan walks back over whole attribute groups, so a cfg that is
        // not the nearest attribute must still be found, and nested brackets
        // inside an attribute must not confuse the walk.
        let source = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      #[cfg(feature = \"x\")]\n\
                      #[allow(clippy::type_complexity)]\n\
                      #[doc = \"[not an attribute]\"]\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n";
        assert_eq!(identity_source_uses_expansion(source.as_bytes()), Ok(true));
    }

    #[test]
    fn ordinary_attributes_on_the_second_identity_declaration_are_not_conditional() {
        let source = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      #[allow(dead_code)]\n\
                      #[inline]\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n";
        assert_eq!(identity_source_uses_expansion(source.as_bytes()), Ok(false));
    }

    #[test]
    fn a_cfg_on_an_unrelated_item_before_the_identities_is_found_by_the_other_scan() {
        // The mirror case: only the top-level scan applies, because no
        // identity declaration has been seen yet and the attribute belongs to
        // something else entirely.
        let source = "#[cfg(feature = \"x\")]\n\
                      fn unrelated() {}\n\
                      pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n";
        assert_eq!(identity_source_uses_expansion(source.as_bytes()), Ok(true));
    }

    #[test]
    fn an_unbalanced_attribute_bracket_is_not_read_as_a_cfg() {
        // The walk back from a declaration counts brackets to find where the
        // attribute began. If it runs off the front of the token stream the
        // answer is unknown, and reporting "no cfg here" on a guess would let
        // a conditional identity through the integrity check.
        let source = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      cfg]\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n";
        // The stray bracket is unbalanced, so the source is refused outright
        // rather than being read as an attribute that happens to say cfg.
        assert!(identity_source_uses_expansion(source.as_bytes()).is_err());
    }

    #[test]
    fn a_cfg_attr_on_the_second_identity_declaration_counts_too() {
        // `cfg_attr` can attach a further attribute conditionally, so it can
        // select behaviour just as `cfg` selects presence.
        let source = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      #[cfg_attr(feature = \"x\", allow(dead_code))]\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n";
        assert_eq!(identity_source_uses_expansion(source.as_bytes()), Ok(true));
    }

    #[test]
    fn a_cfg_attribute_before_the_declaration_makes_it_conditional() {
        // Anything that can select between declarations must force the
        // compiled comparison, or a build could ship a different constant
        // than the one this file appears to declare.
        for attribute in [
            "#[cfg(feature = \"x\")]\n",
            "#[cfg_attr(feature = \"x\", allow(dead_code))]\n",
            "#![cfg(feature = \"x\")]\n",
            "#[inline]\n#[cfg(feature = \"x\")]\n",
            "#[cfg(feature = \"x\")]\n#[inline]\n",
        ] {
            assert_eq!(
                identity_source_uses_expansion(&identity_source_with(attribute)),
                Ok(true),
                "attribute={attribute}"
            );
        }
    }

    #[test]
    fn an_attribute_that_cannot_select_a_declaration_is_not_expansion() {
        for attribute in [
            "#[inline]\n",
            "#[allow(dead_code)]\n",
            "#[doc = \"text\"]\n",
        ] {
            assert_eq!(
                identity_source_uses_expansion(&identity_source_with(attribute)),
                Ok(false),
                "attribute={attribute}"
            );
        }
    }

    #[test]
    fn a_cfg_inside_a_body_does_not_make_the_declarations_conditional() {
        // Only a top-level attribute can select the declaration; one nested in
        // a function body decides something else entirely.
        let source = "fn helper() {\n    #[cfg(feature = \"x\")]\n    let _ = 1;\n}\n";
        assert_eq!(
            identity_source_uses_expansion(&identity_source_with(source)),
            Ok(false)
        );
    }

    #[test]
    fn a_word_that_merely_starts_with_include_is_not_an_include() {
        let source = "fn included_helper() {}\n";
        assert_eq!(
            identity_source_uses_expansion(&identity_source_with(source)),
            Ok(false)
        );
    }

    #[test]
    fn an_identity_source_that_is_not_utf8_is_refused() {
        assert!(identity_source_uses_expansion(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn a_cfg_attribute_after_the_declaration_is_not_expansion_of_it() {
        // The guard asks whether the *identity* declaration is conditional.
        // An attribute that appears only after both declarations cannot
        // select them.
        let source = "pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str = \"00\";\n\
                      pub const R17_BENCHMARK_SPEC_SHA256: [u8; 32] = [0; 32];\n\
                      #[cfg(feature = \"x\")]\n\
                      fn unrelated() {}\n";
        assert_eq!(identity_source_uses_expansion(source.as_bytes()), Ok(false));
    }
}

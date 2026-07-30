use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use super::envelope::{CaseEnvelope, MAX_ENVELOPE_LEN};

pub const ARTIFACT_DIR_ENV: &str = "RUSTER_R16A_ARTIFACT_DIR";
pub const REPLAY_ENV: &str = "RUSTER_R16A_REPLAY";
const MAX_DETAIL_BYTES: usize = 4_096;
const MAX_JSONL_BYTES: usize = 65_536;

pub struct ArtifactWriter {
    directory: PathBuf,
}

pub struct ArtifactRecord {
    pub case_path: PathBuf,
    pub jsonl_path: PathBuf,
    pub repro: String,
}

impl ArtifactWriter {
    pub fn from_env() -> Result<Option<Self>, String> {
        match env::var(ARTIFACT_DIR_ENV) {
            Ok(value) => Self::new(PathBuf::from(value)).map(Some),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                Err(format!("{ARTIFACT_DIR_ENV} must be valid UTF-8"))
            }
        }
    }

    pub fn new(directory: PathBuf) -> Result<Self, String> {
        validate_absolute_path(&directory, "artifact directory")?;
        if directory == Path::new("/") {
            return Err("artifact directory cannot be filesystem root".to_owned());
        }
        Ok(Self { directory })
    }

    pub fn write(
        &self,
        encoded: &[u8],
        case: &CaseEnvelope<'_>,
        detail: &str,
    ) -> Result<ArtifactRecord, String> {
        if encoded.len() > MAX_ENVELOPE_LEN {
            return Err("refusing to write oversized replay envelope".to_owned());
        }
        validate_no_symlink_components(&self.directory, "artifact directory", true)?;
        match create_private_dir(&self.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create private artifact directory: {error}")),
        }
        let metadata = fs::symlink_metadata(&self.directory)
            .map_err(|error| format!("inspect artifact directory: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("artifact directory must be a real directory, not a symlink".to_owned());
        }
        validate_private_directory(&metadata)?;

        let stem = format!(
            "r16a-{}-{:016x}-{:016x}",
            case.target.name(),
            case.seed,
            case.case_index
        );
        for suffix in 0_u8..16 {
            let unique = if suffix == 0 {
                stem.clone()
            } else {
                format!("{stem}-{suffix}")
            };
            let case_path = self.directory.join(format!("{unique}.case"));
            let jsonl_path = self.directory.join(format!("{unique}.jsonl"));
            let mut case_file = match create_new(&case_path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("create replay envelope: {error}")),
            };
            if let Err(error) = secure_created_file(&case_file, &metadata) {
                drop(case_file);
                return Err(failed_artifact_transaction(&error, &[&case_path]));
            }
            if let Err(error) = case_file.write_all(encoded) {
                drop(case_file);
                return Err(failed_artifact_transaction(
                    &format!("write replay envelope: {error}"),
                    &[&case_path],
                ));
            }
            let repro = match replay_repro(&case_path) {
                Ok(repro) => repro,
                Err(error) => {
                    drop(case_file);
                    return Err(failed_artifact_transaction(
                        &format!("build replay command: {error}"),
                        &[&case_path],
                    ));
                }
            };
            let mut metadata_file = match create_new(&jsonl_path) {
                Ok(file) => file,
                Err(error) => {
                    drop(case_file);
                    if let Err(cleanup_error) = fs::remove_file(&case_path) {
                        return Err(format!(
                            "create artifact metadata: {error}; cleanup replay envelope: \
                             {cleanup_error}"
                        ));
                    }
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    return Err(format!("create artifact metadata: {error}"));
                }
            };
            if let Err(error) = secure_created_file(&metadata_file, &metadata) {
                drop(case_file);
                drop(metadata_file);
                return Err(failed_artifact_transaction(
                    &error,
                    &[&case_path, &jsonl_path],
                ));
            }
            let git_sha = validated_git_sha();
            let detail = bounded_detail(detail);
            let line = format!(
                "{{\"schema\":1,\"git_sha\":\"{}\",\"target\":\"{}\",\
                 \"seed\":\"0x{:016x}\",\"case\":{},\"case_path\":\"{}\",\
                 \"detail\":\"{}\",\"repro\":\"{}\"}}\n",
                json_escape(&git_sha),
                case.target.name(),
                case.seed,
                case.case_index,
                json_escape(case_path.to_str().expect("validated UTF-8 path")),
                json_escape(&detail),
                json_escape(&repro),
            );
            if line.len() > MAX_JSONL_BYTES {
                drop(case_file);
                drop(metadata_file);
                return Err(failed_artifact_transaction(
                    "artifact metadata exceeds 65536-byte limit",
                    &[&case_path, &jsonl_path],
                ));
            }
            if let Err(error) = metadata_file.write_all(line.as_bytes()) {
                drop(case_file);
                drop(metadata_file);
                return Err(failed_artifact_transaction(
                    &format!("write artifact metadata: {error}"),
                    &[&case_path, &jsonl_path],
                ));
            }
            return Ok(ArtifactRecord {
                case_path,
                jsonl_path,
                repro,
            });
        }
        Err("all 16 bounded artifact names already exist".to_owned())
    }
}

pub fn load_replay_from_env() -> Result<Option<(PathBuf, Vec<u8>)>, String> {
    let value = match env::var(REPLAY_ENV) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!("{REPLAY_ENV} must be valid UTF-8"));
        }
    };
    let path = PathBuf::from(value);
    load_replay(path).map(Some)
}

pub fn load_replay(path: PathBuf) -> Result<(PathBuf, Vec<u8>), String> {
    validate_absolute_path(&path, "replay path")?;
    validate_no_symlink_components(&path, "replay path", false)?;
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|error| format!("inspect replay path: {error}"))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err("replay path must be one regular file, not a symlink".to_owned());
    }
    let file = File::open(&path).map_err(|error| format!("open replay file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect opened replay file: {error}"))?;
    if !metadata.is_file() {
        return Err("replay path must open as one regular file".to_owned());
    }
    let length =
        usize::try_from(metadata.len()).map_err(|_| "replay file length overflow".to_owned())?;
    if length > MAX_ENVELOPE_LEN {
        return Err(format!(
            "replay file exceeds {MAX_ENVELOPE_LEN}-byte envelope limit"
        ));
    }
    let mut bytes = Vec::with_capacity(length.saturating_add(1));
    file.take(u64::try_from(MAX_ENVELOPE_LEN).unwrap() + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read replay file: {error}"))?;
    if bytes.len() > MAX_ENVELOPE_LEN {
        return Err(format!(
            "replay file exceeds {MAX_ENVELOPE_LEN}-byte envelope limit"
        ));
    }
    Ok((path, bytes))
}

pub fn seed_repro(target: &str, seed: u64, case_index: u64) -> String {
    format!(
        "RUSTER_R16A_TARGET={target} RUSTER_R16A_SEED=0x{seed:016x} \
         RUSTER_R16A_CASE_START={case_index} RUSTER_R16A_CASES=1 \
         cargo test --locked -p ruster-io-sim --test security_property_smoke \
         r16a_bounded_smoke -- --ignored --exact --nocapture --test-threads=1"
    )
}

pub fn replay_repro(path: &Path) -> Result<String, String> {
    validate_absolute_path(path, "replay path")?;
    Ok(format!(
        "{REPLAY_ENV}={} cargo test --locked -p ruster-io-sim \
         --test security_property_smoke r16a_bounded_smoke -- \
         --ignored --exact --nocapture --test-threads=1",
        path.to_str().expect("validated UTF-8 path")
    ))
}

fn create_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err("artifact directory must have private mode 0700".to_owned());
        }
    }
    Ok(())
}

fn secure_created_file(file: &File, directory: &fs::Metadata) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("set private artifact file mode: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect created artifact file: {error}"))?;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err("artifact file must have private mode 0600".to_owned());
        }
        if metadata.uid() != directory.uid() {
            return Err("artifact directory must be owned by the artifact writer user".to_owned());
        }
    }
    Ok(())
}

fn validate_no_symlink_components(
    path: &Path,
    label: &str,
    allow_missing_leaf: bool,
) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{label} cannot traverse symlinks"));
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && allow_missing_leaf
                    && index + 1 == components.len() => {}
            Err(error) => return Err(format!("inspect {label} component: {error}")),
        }
    }
    Ok(())
}

fn failed_artifact_transaction(context: &str, created: &[&Path]) -> String {
    let mut cleanup_failures = String::new();
    for path in created {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                use std::fmt::Write;
                write!(
                    &mut cleanup_failures,
                    " cleanup {}: {error};",
                    path.display()
                )
                .unwrap();
            }
        }
    }
    if cleanup_failures.is_empty() {
        context.to_owned()
    } else {
        format!("{context};{cleanup_failures}")
    }
}

fn bounded_detail(detail: &str) -> String {
    const MARKER: &str = "...[truncated]";
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail.to_owned();
    }
    let mut end = MAX_DETAIL_BYTES - MARKER.len();
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = detail[..end].to_owned();
    bounded.push_str(MARKER);
    bounded
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{label} must be valid UTF-8"))?;
    if !path.is_absolute() {
        return Err(format!("{label} must be explicit and absolute"));
    }
    if text.len() > 4_096 {
        return Err(format!("{label} exceeds 4096 bytes"));
    }
    if !text.bytes().all(
        |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'/' | b'_' | b'-' | b'.' | b':'),
    ) {
        return Err(format!("{label} contains unsupported characters"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        )
    }) {
        return Err(format!("{label} must be canonical without dot components"));
    }
    Ok(())
}

fn validated_git_sha() -> String {
    match env::var("GITHUB_SHA") {
        Ok(value)
            if value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
        {
            value
        }
        _ => "unknown".to_owned(),
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                write!(&mut escaped, "\\u{:04x}", u32::from(character)).unwrap();
            }
            character => escaped.push(character),
        }
    }
    escaped
}

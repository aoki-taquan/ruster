use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ruster-bench-r17-identity-cfg-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary identity directory must be creatable");
        Self { path }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn r17_identity_parser_rejects_cfg_and_include_tampering() {
    let temporary = TemporaryDirectory::new();
    let candidate = temporary.path("identity.rs");
    let included = temporary.path("tampered_identity.rs");
    fs::write(
        &candidate,
        r#"#[cfg(any())]
pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([
    0x57, 0x37, 0x20, 0xcd, 0xe7, 0xbb, 0xd5, 0x22, 0xee, 0x8f, 0x54, 0x86, 0x8b, 0x41, 0xbb, 0xf2,
    0x5e, 0xee, 0x9e, 0x3c, 0xb2, 0x27, 0xa9, 0x45, 0x53, 0xb5, 0x44, 0x11, 0xe1, 0x20, 0xde, 0x9d,
]);
#[cfg(any())]
pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str =
    "573720cde7bbd522ee8f54868b41bbf25eee9e3cb227a94553b54411e120de9d";
#[cfg(not(any()))]
include!("tampered_identity.rs");
"#,
    )
    .expect("candidate identity must be writable");
    fs::write(
        &included,
        r#"pub const R17_BENCHMARK_SPEC_SHA256: Sha256Digest = Sha256Digest::from_bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
pub const R17_BENCHMARK_SPEC_SHA256_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
"#,
    )
    .expect("included identity must be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_ruster-bench"))
        .args(["--parse-benchmark-identity", candidate.to_str().unwrap()])
        .output()
        .expect("identity parser executable must start");
    assert!(!output.status.success(), "tampered identity was accepted");
    assert!(
        output.stdout.is_empty(),
        "rejected identity must not print values"
    );

    let canonical = temporary.path("canonical_identity.rs");
    fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/spec.rs"),
        &canonical,
    )
    .expect("canonical identity must be copyable");
    let output = Command::new(env!("CARGO_BIN_EXE_ruster-bench"))
        .args(["--parse-benchmark-identity", canonical.to_str().unwrap()])
        .output()
        .expect("identity parser executable must start");
    assert!(output.status.success(), "canonical identity was rejected");
    assert_eq!(
        output.stdout,
        format!(
            "benchmark_compiled_sha256={}\nbenchmark_typed_sha256={}\n",
            ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX,
            ruster_bench::R17_BENCHMARK_SPEC_SHA256_HEX,
        )
        .into_bytes()
    );
    assert!(
        output.stderr.is_empty(),
        "canonical identity emitted stderr"
    );
}

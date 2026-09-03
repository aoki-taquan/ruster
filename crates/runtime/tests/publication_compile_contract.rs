use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct CompileFixture {
    root: PathBuf,
    manifest: PathBuf,
    source: PathBuf,
    target: PathBuf,
}

impl CompileFixture {
    fn new(label: &str) -> Self {
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "ruster-runtime-{label}-{}-{fixture_id}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap_or_else(|error| {
            panic!(
                "failed to create compile fixture {}: {error}",
                root.display()
            )
        });

        let fixture = Self {
            manifest: root.join("Cargo.toml"),
            source: root.join("src/main.rs"),
            target: root.join("target"),
            root,
        };
        fs::create_dir(fixture.source.parent().expect("source has one parent")).unwrap_or_else(
            |error| {
                panic!(
                    "failed to create compile fixture source directory {}: {error}",
                    fixture.root.display()
                )
            },
        );

        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let runtime_path = toml_path(manifest_dir);
        let core_path = toml_path(
            &manifest_dir
                .parent()
                .expect("workspace crates directory")
                .join("core"),
        );
        let io_sim_path = toml_path(
            &manifest_dir
                .parent()
                .expect("workspace crates directory")
                .join("io-sim"),
        );
        let manifest = format!(
            "[package]\nname = \"ruster-runtime-compile-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nruster-runtime = {{ path = \"{runtime_path}\" }}\nruster-core = {{ path = \"{core_path}\" }}\nruster-io-sim = {{ path = \"{io_sim_path}\" }}\n"
        );
        fs::write(&fixture.manifest, manifest).unwrap_or_else(|error| {
            panic!(
                "failed to write compile fixture manifest {}: {error}",
                fixture.manifest.display()
            )
        });
        fixture
    }

    fn check(&self, source: &str) -> Output {
        fs::write(&self.source, source).unwrap_or_else(|error| {
            panic!(
                "failed to write compile fixture source {}: {error}",
                self.source.display()
            )
        });

        Command::new(env!("CARGO"))
            .arg("check")
            .arg("--offline")
            .arg("--quiet")
            .arg("--manifest-path")
            .arg(&self.manifest)
            .env("CARGO_TARGET_DIR", &self.target)
            .env("CARGO_TERM_COLOR", "never")
            .env("NO_COLOR", "1")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("RUST_BACKTRACE", "0")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "failed to execute cargo for compile fixture {}: {error}",
                    self.root.display()
                )
            })
    }

    fn assert_compiles(&self, source: &str) {
        let output = self.check(source);
        assert!(
            output.status.success(),
            "positive compile control failed for {}\nstdout:\n{}\nstderr:\n{}",
            self.root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn assert_fails_only_with(&self, source: &str, expected_code: &str) {
        let output = self.check(source);
        assert!(
            !output.status.success(),
            "negative compile fixture unexpectedly succeeded for {}",
            self.root.display()
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        let actual = rustc_error_codes(&stderr);
        let expected = BTreeSet::from([expected_code.to_owned()]);
        assert_eq!(
            actual,
            expected,
            "compile fixture {} produced unexpected diagnostics\nstdout:\n{}\nstderr:\n{stderr}",
            self.root.display(),
            String::from_utf8_lossy(&output.stdout)
        );

        let uncoded_errors = stderr
            .lines()
            .filter(|line| {
                line.starts_with("error:") && !line.starts_with("error: could not compile")
            })
            .collect::<Vec<_>>();
        assert!(
            uncoded_errors.is_empty(),
            "compile fixture {} produced unclassified errors {uncoded_errors:?}\nstderr:\n{stderr}",
            self.root.display()
        );
    }
}

impl Drop for CompileFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn rustc_error_codes(stderr: &str) -> BTreeSet<String> {
    stderr
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("error[")?;
            let (code, _) = rest.split_once(']')?;
            (code.len() == 5
                && code.starts_with('E')
                && code[1..].bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| code.to_owned())
        })
        .collect()
}

/// A minimal external `FullServicePublication` adapter. Both `active()` and
/// `publish_candidate_authorized()` are unreachable in `main`, so the
/// fixture only exercises whether the impl block itself type-checks against
/// the unsafe trait boundary, not view/backend construction.
fn full_service_publication_program(unsafe_keyword: &str) -> String {
    format!(
        r#"use ruster_core::{{
    bind_publication_backend, BoundPublicationBackend, MatchedPublicationQuiescenceGuard,
    PublicationOwnerBinding,
}};
use ruster_io_sim::SimIo;
use ruster_runtime::{{
    ActivePublicationStatus, FullServicePublication, FullServiceView, PublicationRejection,
}};

type Backend = BoundPublicationBackend<SimIo>;

struct Fixture {{
    owner_binding: PublicationOwnerBinding<Backend>,
}}

{unsafe_keyword}impl<'storage> FullServicePublication<'storage, Backend> for Fixture {{
    type Candidate = ();
    type Reject = ();
    type ApplyReport = ();

    fn publication_owner_binding(&self) -> &PublicationOwnerBinding<Backend> {{
        &self.owner_binding
    }}

    fn reject_candidate_if_active_stopped(
        &self,
        candidate: Self::Candidate,
    ) -> Result<Self::Candidate, PublicationRejection<Self::Candidate, Self::Reject>> {{
        Ok(candidate)
    }}

    #[allow(unsafe_code)]
    unsafe fn publish_candidate_authorized(
        &mut self,
        _candidate: Self::Candidate,
        _quiescence: MatchedPublicationQuiescenceGuard<'_, Backend>,
    ) -> Result<Self::ApplyReport, PublicationRejection<Self::Candidate, Self::Reject>> {{
        unreachable!()
    }}

    fn active_status(&self) -> ActivePublicationStatus {{
        ActivePublicationStatus::Absent
    }}

    fn active(&mut self) -> FullServiceView<'_, 'storage> {{
        unreachable!()
    }}
}}

fn main() {{
    let (owner_binding, _backend) =
        bind_publication_backend(SimIo::new()).expect("sim binding identity");
    let _fixture = Fixture {{ owner_binding }};
}}
"#
    )
}

#[test]
fn safe_external_full_service_publication_impl_is_e0200_only() {
    let fixture = CompileFixture::new("safe-full-service-publication-impl");
    fixture.assert_compiles(&full_service_publication_program("unsafe "));
    fixture.assert_fails_only_with(&full_service_publication_program(""), "E0200");
}

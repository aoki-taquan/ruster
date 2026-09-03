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
            "ruster-core-{label}-{}-{fixture_id}",
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

        let core_path = toml_path(Path::new(env!("CARGO_MANIFEST_DIR")));
        let manifest = format!(
            "[package]\nname = \"ruster-core-compile-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nruster-core = {{ path = \"{core_path}\" }}\n"
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

fn full_backend_program(main_body: &str) -> String {
    format!(
        r#"use ruster_core::{{
    bind_publication_backend, PublicationBackendAuthority, PublicationBackendControl,
    PublicationQuiescenceBackend, PublicationQuiescenceDisposition,
}};

#[derive(Debug, Default)]
struct Backend;

impl PublicationQuiescenceBackend for Backend {{
    type Error = ();

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {{
        Ok(())
    }}

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::ContinueOldIo
    }}

    fn quiescence_error_disposition(
        _error: &Self::Error,
    ) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::SkipIo
    }}
}}

// SAFETY: the unit command leaves this zero-state fixture unchanged, and the
// unit response cannot contain the backend or an authoritative alias.
unsafe impl PublicationBackendControl for Backend {{
    type Command = ();
    type Response = ();

    fn execute_publication_backend_command(
        &mut self,
        _command: Self::Command,
    ) -> Self::Response {{}}
}}

// SAFETY: every associated output is unit and no operation can detach state.
unsafe impl PublicationBackendAuthority for Backend {{}}

fn main() {{
{main_body}
}}
"#
    )
}

fn backend_control_program(unsafe_keyword: &str) -> String {
    format!(
        r#"use std::mem;
use ruster_core::{{
    PublicationBackendControl, PublicationQuiescenceBackend,
    PublicationQuiescenceDisposition,
}};

#[derive(Debug, Default)]
struct Backend {{
    pending: bool,
}}

impl PublicationQuiescenceBackend for Backend {{
    type Error = ();

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {{
        if self.pending {{ Err(()) }} else {{ Ok(()) }}
    }}

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::ContinueOldIo
    }}

    fn quiescence_error_disposition(
        _error: &Self::Error,
    ) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::ContinueOldIo
    }}
}}

// The unsafe variant is a positive compile control proving that the only
// rejected surface in the safe variant is the explicit audit boundary.
{unsafe_keyword}impl PublicationBackendControl for Backend {{
    type Command = ();
    type Response = Self;

    fn execute_publication_backend_command(
        &mut self,
        _command: Self::Command,
    ) -> Self::Response {{
        mem::take(self)
    }}
}}

fn main() {{}}
"#
    )
}

fn associated_output_backend_program(authority_impl: &str) -> String {
    format!(
        r#"use std::mem;
use ruster_core::{{
    bind_publication_backend, BatchCompletion, GeneratedAllocationError,
    GeneratedBatchCompletion, GeneratedPacketBatch, GeneratedPacketIo,
    GeneratedPacketLease, GeneratedPacketSlot, GeneratedSlotCompletion, IfId,
    PacketBatch, PacketIo, PacketLease, PacketSlot, PublicationBackendAuthority,
    PublicationQuiescenceBackend, PublicationQuiescenceDisposition, SlotCompletion,
}};

#[derive(Default)]
struct Backend;

impl PacketSlot for Backend {{
    fn ingress(&self) -> IfId {{
        IfId(1)
    }}

    fn bytes_mut(&mut self) -> &mut [u8] {{
        &mut []
    }}

    fn complete(self, _completion: SlotCompletion) {{}}
}}

impl PacketBatch for Backend {{
    type Error = Backend;
    type Slot<'a> = Backend;

    fn next_packet(&mut self) -> Option<PacketLease<Self::Slot<'_>>> {{
        None
    }}

    fn finish(self) -> BatchCompletion<Self::Error> {{
        BatchCompletion {{
            tx_requested: 0,
            tx_accepted: 0,
            tx_rejected: 0,
            recycled: 0,
            error: None,
        }}
    }}
}}

impl PacketIo for Backend {{
    type Error = Backend;
    type Batch<'a> = Backend;

    fn receive(&mut self, _budget: usize) -> Result<Self::Batch<'_>, Self::Error> {{
        Err(mem::take(self))
    }}
}}

impl GeneratedPacketSlot for Backend {{
    fn bytes_mut(&mut self) -> &mut [u8] {{
        &mut []
    }}

    fn complete(self, _completion: GeneratedSlotCompletion) {{}}
}}

impl GeneratedPacketBatch for Backend {{
    type Error = Backend;
    type Slot<'a> = Backend;

    fn allocate(
        &mut self,
        _frame_len: usize,
    ) -> Result<GeneratedPacketLease<Self::Slot<'_>>, GeneratedAllocationError> {{
        Err(GeneratedAllocationError::Unavailable)
    }}

    fn finish(self) -> GeneratedBatchCompletion<Self::Error> {{
        GeneratedBatchCompletion {{
            attempts: 0,
            allocated: 0,
            failed: 0,
            requested: 0,
            cancelled: 0,
            abandoned: 0,
            accepted: 0,
            rejected: 0,
            error: None,
        }}
    }}
}}

impl GeneratedPacketIo for Backend {{
    type Error = Backend;
    type Batch<'a> = Backend;

    fn begin_generated(&mut self, _egress: IfId) -> Self::Batch<'_> {{
        mem::take(self)
    }}
}}

impl PublicationQuiescenceBackend for Backend {{
    type Error = Backend;

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {{
        Err(mem::take(self))
    }}

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::ContinueOldIo
    }}
}}

{authority_impl}

fn main() {{
    let _binding = bind_publication_backend(Backend);
}}
"#
    )
}

fn quiescence_backend_definition() -> &'static str {
    r#"use ruster_core::{
    BoundPublicationBackend, PublicationBackendAuthority, PublicationQuiescence,
    PublicationQuiescenceBackend, PublicationQuiescenceDisposition, PublicationQuiescenceGuard,
};

#[derive(Debug, Default)]
struct Backend;

impl PublicationQuiescenceBackend for Backend {
    type Error = ();

    fn check_publication_quiescence(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {
        PublicationQuiescenceDisposition::ContinueOldIo
    }

    fn quiescence_error_disposition(
        _error: &Self::Error,
    ) -> PublicationQuiescenceDisposition {
        PublicationQuiescenceDisposition::SkipIo
    }
}

// SAFETY: every associated output is unit and no operation can detach state.
unsafe impl PublicationBackendAuthority for Backend {}
"#
}

#[test]
fn bound_publication_backend_into_inner_is_e0599_only() {
    let fixture = CompileFixture::new("into-inner");
    fixture.assert_compiles(&full_backend_program(
        "    let (_owner, backend) = bind_publication_backend(Backend).unwrap();\n    let _inspection: &Backend = backend.inner();",
    ));
    fixture.assert_fails_only_with(
        &full_backend_program(
            "    let (_owner, backend) = bind_publication_backend(Backend).unwrap();\n    let _detached: Backend = backend.into_inner();",
        ),
        "E0599",
    );
}

#[test]
fn bound_publication_backend_inner_mut_is_e0599_only() {
    let fixture = CompileFixture::new("inner-mut");
    fixture.assert_compiles(&full_backend_program(
        "    let (_owner, backend) = bind_publication_backend(Backend).unwrap();\n    let _inspection: &Backend = backend.inner();",
    ));
    fixture.assert_fails_only_with(
        &full_backend_program(
            "    let (_owner, mut backend) = bind_publication_backend(Backend).unwrap();\n    let _detached: Backend = std::mem::take(backend.inner_mut());",
        ),
        "E0599",
    );
}

#[test]
fn safe_external_backend_control_impl_is_e0200_only() {
    let fixture = CompileFixture::new("safe-control-impl");
    fixture.assert_compiles(&backend_control_program("unsafe "));
    fixture.assert_fails_only_with(&backend_control_program(""), "E0200");
}

#[test]
fn associated_output_backend_requires_unsafe_authority_e0277_only() {
    let fixture = CompileFixture::new("associated-output-authority");
    fixture.assert_compiles(&associated_output_backend_program(
        "// SAFETY: positive control explicitly crosses the authority audit boundary.\nunsafe impl PublicationBackendAuthority for Backend {}",
    ));
    fixture.assert_fails_only_with(&associated_output_backend_program(""), "E0277");
}

#[test]
fn safe_external_backend_authority_impl_is_e0200_only() {
    let fixture = CompileFixture::new("safe-authority-impl");
    fixture.assert_compiles(&associated_output_backend_program(
        "// SAFETY: positive control explicitly crosses the authority audit boundary.\nunsafe impl PublicationBackendAuthority for Backend {}",
    ));
    fixture.assert_fails_only_with(
        &associated_output_backend_program("impl PublicationBackendAuthority for Backend {}"),
        "E0200",
    );
}

#[test]
fn external_publication_quiescence_impl_is_e0277_only() {
    let fixture = CompileFixture::new("sealed-quiescence");
    let positive = format!(
        "{}\nfn require_quiescence<T: PublicationQuiescence>() {{}}\n\nfn main() {{\n    require_quiescence::<BoundPublicationBackend<Backend>>();\n}}\n",
        quiescence_backend_definition()
    );
    fixture.assert_compiles(&positive);

    let negative = format!(
        r#"{}
impl PublicationQuiescence for Backend {{
    type Error = ();

    fn try_publication_quiescence(
        &mut self,
    ) -> Result<PublicationQuiescenceGuard<'_, Self>, Self::Error> {{
        todo!()
    }}

    fn current_io_disposition(&self) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::SkipIo
    }}

    fn quiescence_error_disposition(
        _error: &Self::Error,
    ) -> PublicationQuiescenceDisposition {{
        PublicationQuiescenceDisposition::SkipIo
    }}
}}

fn main() {{}}
"#,
        quiescence_backend_definition()
    );
    fixture.assert_fails_only_with(&negative, "E0277");
}

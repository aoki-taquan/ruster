use std::{
    io::{self, ErrorKind, Read},
    num::NonZeroU64,
    path::{Path, PathBuf},
};

use super::{keys_from, OsRandomKeySource, KEY_SET_BYTES};
use crate::{
    plan::tests::{config, ROUTE_CHANGE},
    ConfigBridgeError, KeySourceError, KeySourceKind, ProductionKeySource, ProductionSequencer,
    PublicationKeySource, PublicationSequencer, RuntimeService, SequencerError,
    SimDeterministicKeySource, ValidatedCandidate,
};

fn keys_of(
    candidate: &ValidatedCandidate,
) -> (
    ruster_core::Nat44UdpHashKey,
    ruster_core::Nat44TcpHashKey,
    ruster_core::FirewallHashKey,
) {
    let authority = candidate.authority();
    (
        authority.nat44_udp_hash_key(),
        authority.nat44_tcp_hash_key(),
        authority.firewall_config().hash_key(),
    )
}

fn manifest_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// One scripted `read` outcome.
enum Step {
    Bytes(Vec<u8>),
    Fail(ErrorKind),
}

/// A reader that replays `steps` in order, one per `read` call, and counts
/// calls. Every `Bytes` step must fit the caller's buffer.
struct Scripted {
    steps: Vec<Step>,
    calls: usize,
}

impl Scripted {
    fn new(steps: Vec<Step>) -> Self {
        Self { steps, calls: 0 }
    }
}

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let step = self.steps.get(self.calls);
        self.calls += 1;
        match step {
            None => Ok(0),
            Some(Step::Bytes(bytes)) => {
                buffer[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }
            Some(Step::Fail(kind)) => Err(io::Error::from(*kind)),
        }
    }
}

const PATTERN: [u8; KEY_SET_BYTES] = {
    let mut bytes = [0_u8; KEY_SET_BYTES];
    let mut index = 0;
    while index < KEY_SET_BYTES {
        bytes[index] = index as u8 + 1;
        index += 1;
    }
    bytes
};

#[test]
fn os_random_source_draws_distinct_keys_for_every_publication() {
    let a = config(&[]);
    let b = config(&[ROUTE_CHANGE]);
    let mut sequencer = ProductionSequencer::new(OsRandomKeySource::open().expect("urandom"));
    assert_eq!(sequencer.last_issued(), None);
    assert_eq!(sequencer.next_generation(), Ok(NonZeroU64::MIN));
    // A→B→A rollback and further reloads: each is a new generation with
    // fresh keys; numbering and reuse rejection are the sequencer's.
    let issued: Vec<_> = [&a, &b, &a, &b, &a, &a, &b, &a]
        .into_iter()
        .map(|config| sequencer.candidate(config).expect("candidate"))
        .collect();
    let generations: Vec<_> = issued
        .iter()
        .map(|candidate| candidate.generation().get())
        .collect();
    assert_eq!(generations, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(sequencer.last_issued().map(NonZeroU64::get), Some(8));
    let keys: Vec<_> = issued.iter().map(keys_of).collect();
    for (index, left) in keys.iter().enumerate() {
        for right in &keys[index + 1..] {
            assert!(left.0 != right.0 && left.1 != right.1 && left.2 != right.2);
        }
    }
    for pair in issued.windows(2) {
        pair[0].validate_successor(&pair[1]).expect("successor");
    }
    // The rollback (generation 3, document A) is a valid successor of A's
    // original generation too.
    issued[0].validate_successor(&issued[2]).expect("rollback");

    // Two independently opened sources do not repeat each other either.
    let mut first = OsRandomKeySource::open().unwrap();
    let mut second = OsRandomKeySource::open().unwrap();
    let left = first.publication_keys(NonZeroU64::MIN).unwrap();
    let right = second.publication_keys(NonZeroU64::MIN).unwrap();
    assert!(left.nat44_udp() != right.nat44_udp());
    assert!(left.nat44_tcp() != right.nat44_tcp());
    assert!(left.firewall() != right.firewall());
}

/// The negative cases (a simulation source, or a foreign source declaring a
/// production `KIND`) are compile-fail doctests on `ProductionSequencer`,
/// `ProductionKeySource`, and `SimDeterministicKeySource`; this test pins
/// the positive side and the runtime classification of every kind.
#[test]
fn production_guard_rejects_simulation_key_sources() {
    fn require_production<S: ProductionKeySource>() -> KeySourceKind {
        S::KIND
    }
    assert_eq!(
        require_production::<OsRandomKeySource>(),
        KeySourceKind::OperatingSystemRandom
    );
    assert!(KeySourceKind::OperatingSystemRandom.is_production());
    assert!(!KeySourceKind::DeterministicSimulation.is_production());
    assert_eq!(
        SimDeterministicKeySource::KIND,
        KeySourceKind::DeterministicSimulation
    );
    let sequencer = ProductionSequencer::new(OsRandomKeySource::open().unwrap());
    assert_eq!(sequencer.last_issued(), None);
}

#[test]
fn entropy_reads_retry_interrupts_and_continue_short_reads() {
    let mut steps = vec![Step::Fail(ErrorKind::Interrupted)];
    for chunk in PATTERN.chunks(5) {
        steps.push(Step::Bytes(chunk.to_vec()));
        steps.push(Step::Fail(ErrorKind::Interrupted));
    }
    let mut reader = Scripted::new(steps);
    let keys = keys_from(&mut reader).expect("keys");
    let whole = keys_from(&mut Scripted::new(vec![Step::Bytes(PATTERN.to_vec())])).unwrap();
    assert_eq!(keys, whole);
    assert_eq!(reader.calls, 1 + 2 * PATTERN.chunks(5).count() - 1);
}

#[test]
fn entropy_failures_are_typed_and_yield_no_publication() {
    // Read errors other than EINTR, also after a partial read.
    for kind in [
        ErrorKind::Other,
        ErrorKind::PermissionDenied,
        ErrorKind::WouldBlock,
    ] {
        let mut reader = Scripted::new(vec![Step::Bytes(PATTERN[..7].to_vec()), Step::Fail(kind)]);
        assert_eq!(
            keys_from(&mut reader),
            Err(KeySourceError::EntropyRead(kind))
        );
    }
    // End of file before a full key set.
    let mut reader = Scripted::new(vec![Step::Bytes(PATTERN[..KEY_SET_BYTES - 1].to_vec())]);
    assert_eq!(
        keys_from(&mut reader),
        Err(KeySourceError::EntropyEndOfFile)
    );
    // An all-zero key is rejected, never replaced.
    let mut zero_udp = PATTERN;
    zero_udp[..16].fill(0);
    let mut zero_firewall = PATTERN;
    zero_firewall[32..].fill(0);
    for (bytes, service) in [
        (zero_udp, RuntimeService::Nat44Udp),
        (zero_firewall, RuntimeService::Firewall),
    ] {
        assert_eq!(
            keys_from(&mut Scripted::new(vec![Step::Bytes(bytes.to_vec())])),
            Err(KeySourceError::AllZeroKey(service))
        );
    }

    // Unopenable or wrong-kind devices fail at construction.
    assert_eq!(
        OsRandomKeySource::open_at(&manifest_path("no-such-entropy-device")).err(),
        Some(KeySourceError::EntropyOpen(ErrorKind::NotFound))
    );
    assert_eq!(
        OsRandomKeySource::open_at(&manifest_path("src")).err(),
        Some(KeySourceError::EntropyNotCharacterDevice)
    );
    assert_eq!(
        OsRandomKeySource::open_at(&manifest_path("Cargo.toml")).err(),
        Some(KeySourceError::EntropyNotCharacterDevice)
    );

    // A character device that yields no bytes: the sequencer consumes the
    // generation, issues no candidate, and never falls back.
    let empty = OsRandomKeySource::open_at(Path::new("/dev/null")).expect("char device");
    let mut sequencer = ProductionSequencer::new(empty);
    let a = config(&[]);
    for generation in 1..=2 {
        assert_eq!(
            sequencer.candidate(&a).err(),
            Some(SequencerError::Bridge(ConfigBridgeError::KeySource(
                KeySourceError::EntropyEndOfFile
            )))
        );
        assert_eq!(
            sequencer.last_issued().map(NonZeroU64::get),
            Some(generation)
        );
    }
    assert_eq!(
        ConfigBridgeError::KeySource(KeySourceError::EntropyEndOfFile).code(),
        "KEY_SOURCE"
    );
}

#[test]
fn production_sequencer_keeps_sim_sequencer_semantics() {
    // The run-sim path is unchanged: the deterministic source still drives a
    // plain sequencer and reproduces its keys exactly.
    let a = config(&[]);
    let mut first = PublicationSequencer::new(SimDeterministicKeySource::new(9));
    let mut second = PublicationSequencer::new(SimDeterministicKeySource::new(9));
    let left = first.candidate(&a).unwrap();
    let right = second.candidate(&a).unwrap();
    assert!(keys_of(&left) == keys_of(&right));

    let mut production = ProductionSequencer::new(OsRandomKeySource::open().unwrap());
    let candidate = production.candidate(&a).unwrap();
    assert_eq!(candidate.generation(), left.generation());
    assert!(keys_of(&candidate).0 != keys_of(&left).0);
}

#[test]
fn os_random_source_and_errors_are_redacted() {
    let mut source = OsRandomKeySource::open().unwrap();
    assert_eq!(format!("{source:?}"), "OsRandomKeySource([REDACTED])");
    assert_eq!(format!("{source:#?}"), "OsRandomKeySource([REDACTED])");
    let keys = source.publication_keys(NonZeroU64::MIN).unwrap();
    assert_eq!(format!("{keys:?}"), "PublicationKeys([REDACTED])");

    let mut sequencer = ProductionSequencer::new(source);
    sequencer.candidate(&config(&[])).unwrap();
    assert_eq!(
        format!("{sequencer:?}"),
        "ProductionSequencer { last_issued: Some(1), issued_key_sets: 1, .. }"
    );

    let mut reader = Scripted::new(vec![
        Step::Bytes(PATTERN[..9].to_vec()),
        Step::Fail(ErrorKind::Other),
    ]);
    let error = keys_from(&mut reader).unwrap_err();
    let rendered = format!(
        "{:?}",
        SequencerError::Bridge(ConfigBridgeError::KeySource(error))
    );
    assert_eq!(rendered, "Bridge(KeySource(EntropyRead(Other)))");
    for error in [
        KeySourceError::EntropyOpen(ErrorKind::NotFound),
        KeySourceError::EntropyNotCharacterDevice,
        KeySourceError::EntropyEndOfFile,
    ] {
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("urandom") && !rendered.contains('/'));
    }
}

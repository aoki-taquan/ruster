//! Production publication key source backed by the operating system CSPRNG,
//! and the sealed marker that production entry points require.
//!
//! [`OsRandomKeySource`] reads `/dev/urandom` through `std` (no new
//! dependency, no `unsafe`). On kernels before 5.18 `/dev/urandom` may serve
//! output from a not yet seeded CRNG early in boot; `getrandom(2)` is a
//! follow-up. The device is opened once, by
//! [`OsRandomKeySource::open`], and must be the Linux `/dev/urandom` (1:9)
//! or `/dev/random` (1:8) character device. Each
//! publication draws 48 fresh bytes (two 64-bit words for each of the UDP
//! NAT44, TCP NAT44, and firewall keys). Short reads are continued,
//! `EINTR` is retried, and every other outcome is a typed, value-free
//! [`KeySourceError`]. There is no fallback: a failed draw yields no key set
//! and therefore no candidate.
//!
//! [`ProductionKeySource`] is sealed and implemented only by
//! [`OsRandomKeySource`], so [`crate::ProductionSequencer`] (the sequencer the
//! live `run` path uses) cannot be built from
//! [`crate::SimDeterministicKeySource`] or any other
//! [`KeySourceKind::DeterministicSimulation`] source.
//!
//! # Secret hygiene
//!
//! Formatting is redacted and errors carry only an [`std::io::ErrorKind`].
//! Key bytes are not zeroized on drop: the core key types are `Copy` and are
//! replicated into the candidate authority and every runtime for the lifetime
//! of the generation, and a guaranteed scrub needs volatile writes (`unsafe`,
//! forbidden in this crate) or a new dependency. Scrubbing the transient read
//! buffer alone would promise nothing, so it is not attempted.

use std::{
    fmt,
    fs::File,
    io::{ErrorKind, Read},
    num::NonZeroU64,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
};

use ruster_core::{FirewallHashKey, Nat44TcpHashKey, Nat44UdpHashKey};

use crate::{
    config_bridge::{KeySourceError, KeySourceKind, PublicationKeySource, PublicationKeys},
    publication::RuntimeService,
};

/// The kernel CSPRNG device.
const DEVICE: &str = "/dev/urandom";

/// Bytes drawn per publication: three keys of two `u64` words each.
const KEY_SET_BYTES: usize = 48;

/// Linux `(major, minor)` numbers of the kernel CSPRNG devices:
/// `/dev/urandom` (1:9) and `/dev/random` (1:8).
const CSPRNG_DEVICES: &[(u64, u64)] = &[(1, 9), (1, 8)];

/// Splits a Linux `dev_t` into `(major, minor)` (glibc/kernel huge encoding,
/// matching `major(3)`/`minor(3)`).
const fn device_numbers(rdev: u64) -> (u64, u64) {
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xffff_f000);
    let minor = (rdev & 0xff) | ((rdev >> 12) & 0xffff_ff00);
    (major, minor)
}

mod sealed {
    pub trait Sealed {}
}

/// Marker for key sources whose keys are unpredictable and therefore safe for
/// live traffic.
///
/// Sealed: only [`OsRandomKeySource`] implements it, so a
/// [`KeySourceKind::DeterministicSimulation`] source cannot satisfy a
/// production bound. [`crate::ProductionSequencer::new`] additionally rejects
/// such a `KIND` at compile time.
///
/// ```compile_fail,E0277
/// use ruster_control::{ProductionKeySource, SimDeterministicKeySource};
///
/// fn require_production<S: ProductionKeySource>() {}
/// require_production::<SimDeterministicKeySource>();
/// ```
///
/// A source outside this crate cannot opt in, even by declaring a
/// production `KIND`:
///
/// ```compile_fail,E0277
/// use std::num::NonZeroU64;
///
/// use ruster_control::{
///     KeySourceError, KeySourceKind, ProductionKeySource, PublicationKeySource, PublicationKeys,
///     SimDeterministicKeySource,
/// };
///
/// struct Mislabeled;
///
/// impl PublicationKeySource for Mislabeled {
///     const KIND: KeySourceKind = KeySourceKind::OperatingSystemRandom;
///
///     fn publication_keys(
///         &mut self,
///         generation: NonZeroU64,
///     ) -> Result<PublicationKeys, KeySourceError> {
///         SimDeterministicKeySource::new(1).publication_keys(generation)
///     }
/// }
///
/// impl ProductionKeySource for Mislabeled {}
/// ```
pub trait ProductionKeySource: PublicationKeySource + sealed::Sealed {}

/// Production key source reading the operating system CSPRNG
/// (`/dev/urandom`).
///
/// Every [`PublicationKeySource::publication_keys`] call draws a fresh key
/// set; the generation argument is not mixed in. Generation numbering and the
/// never-reissue guarantee stay with [`crate::PublicationSequencer`], which
/// rejects an (astronomically unlikely) repeated key as `KeyReused`. Its
/// [`PublicationKeySource::KIND`] is [`KeySourceKind::OperatingSystemRandom`].
///
/// The type is neither `Clone` nor `Copy`, and `Debug` never shows the file
/// descriptor or any drawn byte.
pub struct OsRandomKeySource {
    device: File,
}

impl OsRandomKeySource {
    /// Opens `/dev/urandom`.
    ///
    /// Open the source before dropping privileges or changing root, so the
    /// device stays readable for the whole process.
    pub fn open() -> Result<Self, KeySourceError> {
        Self::open_at(Path::new(DEVICE), CSPRNG_DEVICES)
    }

    /// Opens `path` as the entropy device and requires its device number to
    /// be one of `accepted`. Private seam for failure injection: production
    /// always uses [`DEVICE`] and [`CSPRNG_DEVICES`].
    fn open_at(path: &Path, accepted: &[(u64, u64)]) -> Result<Self, KeySourceError> {
        let device = File::open(path).map_err(|error| KeySourceError::EntropyOpen(error.kind()))?;
        let metadata = device
            .metadata()
            .map_err(|error| KeySourceError::EntropyOpen(error.kind()))?;
        if !metadata.file_type().is_char_device() {
            return Err(KeySourceError::EntropyNotCharacterDevice);
        }
        if !accepted.contains(&device_numbers(metadata.rdev())) {
            return Err(KeySourceError::EntropyUnexpectedDevice);
        }
        Ok(Self { device })
    }
}

impl fmt::Debug for OsRandomKeySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OsRandomKeySource([REDACTED])")
    }
}

impl sealed::Sealed for OsRandomKeySource {}
impl ProductionKeySource for OsRandomKeySource {}

impl PublicationKeySource for OsRandomKeySource {
    const KIND: KeySourceKind = KeySourceKind::OperatingSystemRandom;

    fn publication_keys(&mut self, _: NonZeroU64) -> Result<PublicationKeys, KeySourceError> {
        keys_from(&mut self.device)
    }
}

/// Draws one key set from `entropy`.
fn keys_from<R: Read>(entropy: &mut R) -> Result<PublicationKeys, KeySourceError> {
    let mut bytes = [0_u8; KEY_SET_BYTES];
    fill(entropy, &mut bytes)?;
    let word = |index: usize| {
        let mut chunk = [0_u8; 8];
        chunk.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        u64::from_ne_bytes(chunk)
    };
    let udp = Nat44UdpHashKey::new(word(0), word(1))
        .map_err(|_| KeySourceError::AllZeroKey(RuntimeService::Nat44Udp))?;
    let tcp = Nat44TcpHashKey::new(word(2), word(3))
        .map_err(|_| KeySourceError::AllZeroKey(RuntimeService::Nat44Tcp))?;
    let firewall = FirewallHashKey::new(word(4), word(5))
        .map_err(|_| KeySourceError::AllZeroKey(RuntimeService::Firewall))?;
    Ok(PublicationKeys::new(udp, tcp, firewall))
}

/// Fills `buffer` completely, continuing short reads and retrying `EINTR`.
fn fill<R: Read>(entropy: &mut R, buffer: &mut [u8]) -> Result<(), KeySourceError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match entropy.read(&mut buffer[filled..]) {
            Ok(0) => return Err(KeySourceError::EntropyEndOfFile),
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(KeySourceError::EntropyRead(error.kind())),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;

//! Receive offloads of an AF_PACKET port (AFPKT-015): whether the device
//! merges received frames before a packet socket sees them.
//!
//! A packet socket's RX tap runs after GRO, so with generic receive offload
//! (`rx-gro`), large receive offload (`rx-lro`), or hardware GRO
//! (`rx-gro-hw`) active, the socket receives merged super-frames longer
//! than the MTU. The AF_PACKET RX ring holds at most the configured maximum
//! frame, so the kernel truncates them and the backend drops every one as
//! a packet fault: TCP through the router stalls under load without a
//! hard error. `ruster run` therefore refuses an AF_PACKET port with any of
//! the three active (`RECEIVE_OFFLOAD feature=...`; `ethtool -K <dev> gro
//! off lro off` turns them off; hardware GRO is under GRO), and an
//! unreadable feature set is unverifiable (fail closed). Software GRO
//! sub-features (`rx-gro-list`, `rx-udp-gro-forwarding`) run only inside
//! GRO, so `rx-gro` off covers them.
//!
//! The probe uses the `SIOCETHTOOL` ioctl, once per port at startup
//! (before the privilege drop and the syscall filter): the feature names
//! (`ETHTOOL_GSSET_INFO`, `ETHTOOL_GSTRINGS` of `ETH_SS_FEATURES`) and the
//! active feature words (`ETHTOOL_GFEATURES`). Feature bit numbers are
//! kernel-internal and differ between versions, so they are looked up by
//! name. None of these commands needs a capability. The byte layouts are
//! pure functions here, tested without a kernel; the ioctl is in the
//! private `sys` module.

use std::fmt;

/// `ETH_GSTRING_LEN`.
pub const GSTRING_LEN: usize = 32;
/// `ETH_SS_FEATURES`.
pub const SS_FEATURES: u32 = 4;
/// `ETHTOOL_GSTRINGS`.
pub const GSTRINGS: u32 = 0x1b;
/// `ETHTOOL_GSSET_INFO`.
pub const GSSET_INFO: u32 = 0x37;
/// `ETHTOOL_GFEATURES`.
pub const GFEATURES: u32 = 0x3a;
/// More feature strings than any kernel has (about 70 in Linux 6.x): a
/// count above it is refused as malformed instead of sizing a buffer by it.
pub const MAX_FEATURES: usize = 1_024;

/// A receive offload that merges frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Offload {
    /// `rx-gro` (`NETIF_F_GRO`).
    Gro,
    /// `rx-lro` (`NETIF_F_LRO`).
    Lro,
    /// `rx-gro-hw` (`NETIF_F_GRO_HW`).
    GroHw,
}

impl Offload {
    /// Every checked offload, in report order.
    pub const ALL: [Self; 3] = [Self::Gro, Self::Lro, Self::GroHw];

    /// The kernel's feature string (`netdev_features_strings`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gro => "rx-gro",
            Self::Lro => "rx-lro",
            Self::GroHw => "rx-gro-hw",
        }
    }
}

impl fmt::Display for Offload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// Why the active receive offloads could not be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffloadError {
    /// A syscall failed with this errno.
    Errno(i32),
    /// A reply did not have the expected shape (or more than
    /// [`MAX_FEATURES`] features).
    Malformed,
    /// A checked feature name is not among the kernel's feature strings.
    UnknownFeature(Offload),
}

/// One `SIOCETHTOOL` command of the probe. The command buffer is built by
/// [`Command::buffer`] from this value only, sized for everything the
/// kernel writes back for it, so a caller cannot hand the ioctl a buffer
/// that is too short.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// `ETHTOOL_GSSET_INFO` for `ETH_SS_FEATURES`.
    SsetInfo,
    /// `ETHTOOL_GSTRINGS` of the feature strings, into room for
    /// [`MAX_FEATURES`] strings whatever the count (the kernel ignores the
    /// count we pass, see the ioctl's SAFETY comment).
    Strings,
    /// `ETHTOOL_GFEATURES` of `words` feature words.
    Features { words: usize },
}

impl Command {
    /// The request buffer of this command (checked sizes).
    pub fn buffer(self) -> Result<Vec<u8>, OffloadError> {
        match self {
            Self::SsetInfo => Ok(sset_info_request().to_vec()),
            Self::Strings => Ok(strings_request()),
            Self::Features { words } => features_request(words),
        }
    }
}

/// The `ETHTOOL_GSSET_INFO` request for the feature string count: `cmd`,
/// `reserved`, `sset_mask` (one bit, `ETH_SS_FEATURES`), and room for one
/// `u32` count (the kernel writes one per set mask bit).
fn sset_info_request() -> [u8; 20] {
    let mut request = [0_u8; 20];
    request[0..4].copy_from_slice(&GSSET_INFO.to_ne_bytes());
    request[8..16].copy_from_slice(&(1_u64 << SS_FEATURES).to_ne_bytes());
    request
}

/// The feature string count from an answered [`sset_info_request`]: the
/// kernel clears the mask bit of a set it does not know.
pub fn sset_info_count(reply: &[u8]) -> Result<usize, OffloadError> {
    if reply.len() != 20 {
        return Err(OffloadError::Malformed);
    }
    let mask = u64::from_ne_bytes(
        reply[8..16]
            .try_into()
            .map_err(|_| OffloadError::Malformed)?,
    );
    if mask != 1 << SS_FEATURES {
        return Err(OffloadError::Malformed);
    }
    let count = u32::from_ne_bytes(
        reply[16..20]
            .try_into()
            .map_err(|_| OffloadError::Malformed)?,
    );
    let count = usize::try_from(count).map_err(|_| OffloadError::Malformed)?;
    if count == 0 || count > MAX_FEATURES {
        return Err(OffloadError::Malformed);
    }
    Ok(count)
}

/// Bytes of a [`Command::Strings`] buffer: the header and room for
/// [`MAX_FEATURES`] strings (32 KiB).
pub const STRINGS_BUFFER: usize = 12 + MAX_FEATURES * GSTRING_LEN;

/// The `ETHTOOL_GSTRINGS` request for the feature strings: `cmd`,
/// `string_set`, `len` (0: the kernel ignores it), then room for
/// [`MAX_FEATURES`] strings. Fixed size, whatever count the kernel has.
fn strings_request() -> Vec<u8> {
    let mut request = vec![0_u8; STRINGS_BUFFER];
    request[0..4].copy_from_slice(&GSTRINGS.to_ne_bytes());
    request[4..8].copy_from_slice(&SS_FEATURES.to_ne_bytes());
    request
}

/// The feature bit of `name` in an answered [`Command::Strings`] buffer,
/// whose `len` the kernel set to its feature count: it must be the
/// `count` of the `GSSET_INFO` before (1 to [`MAX_FEATURES`]), and only
/// that many strings (each NUL-padded to 32 bytes) are read.
pub fn feature_bit(reply: &[u8], count: usize, name: &str) -> Result<Option<usize>, OffloadError> {
    if reply.len() != STRINGS_BUFFER || count == 0 || count > MAX_FEATURES {
        return Err(OffloadError::Malformed);
    }
    let len = u32::from_ne_bytes(
        reply[8..12]
            .try_into()
            .map_err(|_| OffloadError::Malformed)?,
    );
    if usize::try_from(len).ok() != Some(count) {
        return Err(OffloadError::Malformed);
    }
    let strings = &reply[12..12 + count * GSTRING_LEN];
    Ok(strings.chunks_exact(GSTRING_LEN).position(|string| {
        let end = string
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(GSTRING_LEN);
        &string[..end] == name.as_bytes()
    }))
}

/// Feature words of `count` features.
pub const fn feature_words(count: usize) -> usize {
    count.div_ceil(32)
}

/// The `ETHTOOL_GFEATURES` request for `words` feature words: `cmd`,
/// `size`, then `words` blocks of `available`, `requested`, `active`,
/// `never_changed`. 1 to `feature_words(MAX_FEATURES)` words.
fn features_request(words: usize) -> Result<Vec<u8>, OffloadError> {
    if words == 0 || words > feature_words(MAX_FEATURES) {
        return Err(OffloadError::Malformed);
    }
    let room = words
        .checked_mul(16)
        .and_then(|room| room.checked_add(8))
        .ok_or(OffloadError::Malformed)?;
    let mut request = vec![0_u8; room];
    request[0..4].copy_from_slice(&GFEATURES.to_ne_bytes());
    let size = u32::try_from(words).map_err(|_| OffloadError::Malformed)?;
    request[4..8].copy_from_slice(&size.to_ne_bytes());
    Ok(request)
}

/// Whether feature `bit` is active in an answered [`Command::Features`]
/// buffer. The kernel sets `size` to its own word count
/// (`ETHTOOL_DEV_FEATURE_WORDS`) and copies at most the words asked for: a
/// `size` that does not cover the bit's word, or a buffer without it, is
/// malformed (never read as off).
pub fn feature_active(reply: &[u8], bit: usize) -> Result<bool, OffloadError> {
    let word = bit / 32;
    let size = reply
        .get(4..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or(OffloadError::Malformed)?;
    if usize::try_from(size).map_or(true, |size| size <= word) {
        return Err(OffloadError::Malformed);
    }
    let offset = 8 + word * 16 + 8;
    let active = reply
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or(OffloadError::Malformed)?;
    Ok(active & (1 << (bit % 32)) != 0)
}

/// The first active offload of [`Offload::ALL`], from the feature strings
/// and words read for one device.
pub fn first_active(
    strings: &[u8],
    count: usize,
    features: &[u8],
) -> Result<Option<Offload>, OffloadError> {
    for offload in Offload::ALL {
        let bit = feature_bit(strings, count, offload.name())?
            .ok_or(OffloadError::UnknownFeature(offload))?;
        if feature_active(features, bit)? {
            return Ok(Some(offload));
        }
    }
    Ok(None)
}

/// Linux `SIOCETHTOOL` reader (cold, startup only).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod linux {
    use super::{feature_words, first_active, sset_info_count, Command, Offload, OffloadError};
    use crate::run::netlink::IfName;

    /// The first active merging receive offload of `device`, `None` if
    /// all are off.
    pub fn active_receive_offload(device: IfName) -> Result<Option<Offload>, OffloadError> {
        let socket = sys::Socket::open()?;
        let info = socket.ethtool(device, Command::SsetInfo)?;
        let count = sset_info_count(&info)?;
        let strings = socket.ethtool(device, Command::Strings)?;
        let features = socket.ethtool(
            device,
            Command::Features {
                words: feature_words(count),
            },
        )?;
        first_active(&strings, count, &features)
    }

    #[allow(unsafe_code)]
    mod sys {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::raw::{c_int, c_void};

        use super::super::{Command, OffloadError};
        use crate::run::netlink::{IfName, IFNAMSIZ};

        const AF_INET: c_int = 2;
        const SOCK_DGRAM: c_int = 2;
        const SOCK_CLOEXEC: c_int = 0o2_000_000;
        /// The request type of the C library's `ioctl`: `unsigned long` in
        /// glibc, `int` in musl.
        #[cfg(not(target_env = "musl"))]
        type Request = std::os::raw::c_ulong;
        #[cfg(target_env = "musl")]
        type Request = c_int;
        const SIOCETHTOOL: Request = 0x8946;

        /// Linux `struct ifreq` with the `ifr_data` member (40 bytes on
        /// x86_64: the name, then a 24-byte union whose first member here
        /// is the pointer).
        #[repr(C)]
        struct IfReq {
            name: [u8; IFNAMSIZ],
            data: *mut c_void,
            pad: [u8; 16],
        }

        const _: () = assert!(std::mem::size_of::<IfReq>() == 40);

        extern "C" {
            // `int socket(int, int, int)` and `int ioctl(int, unsigned
            // long, ...)` (glibc; `int ioctl(int, int, ...)` in musl) of
            // the C library std links.
            fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
            fn ioctl(fd: c_int, request: Request, ...) -> c_int;
        }

        fn last_errno() -> OffloadError {
            OffloadError::Errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }

        /// One datagram socket for the ioctls, closed once by [`OwnedFd`].
        pub struct Socket {
            fd: OwnedFd,
        }

        impl Socket {
            pub fn open() -> Result<Self, OffloadError> {
                // SAFETY: `socket` takes three integers and returns a new
                // fd or -1; no memory is passed.
                let fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
                if fd < 0 {
                    return Err(last_errno());
                }
                // SAFETY: `fd` was just returned by `socket`, is open, and
                // is owned by nothing else.
                Ok(Self {
                    fd: unsafe { OwnedFd::from_raw_fd(fd) },
                })
            }

            /// One `SIOCETHTOOL` on `device` for `command`; returns the
            /// command buffer the kernel answered into. The buffer is built
            /// here from the typed command ([`Command::buffer`]), never
            /// handed in, so its size always matches what the kernel
            /// writes for that command.
            pub fn ethtool(
                &self,
                device: IfName,
                command: Command,
            ) -> Result<Vec<u8>, OffloadError> {
                let mut buffer = command.buffer()?;
                let mut request = IfReq {
                    name: [0; IFNAMSIZ],
                    data: buffer.as_mut_ptr().cast(),
                    pad: [0; 16],
                };
                let name = device.as_bytes();
                // At most IFNAMSIZ - 1 bytes: the name stays NUL-terminated.
                request.name[..name.len()].copy_from_slice(name);
                // SAFETY: `request` is a fully initialized C-layout `ifreq`
                // whose data pointer refers to `buffer`, owned here and
                // live until the call returns. What the kernel writes into
                // it (`net/ethtool/ioctl.c`) stays inside it:
                // - `ETHTOOL_GSSET_INFO` writes the header and one `u32`
                //   per set bit of the 64-bit mask; one bit is set and the
                //   buffer is header plus one `u32` (20 bytes).
                // - `ETHTOOL_GSTRINGS` ignores the `len` we pass: it writes
                //   `len = count` and `count * ETH_GSTRING_LEN` bytes, where
                //   `count` is the kernel's `ETH_SS_FEATURES` count,
                //   `NETDEV_FEATURE_COUNT`: one string per bit of
                //   `netdev_features_t`, a 64-bit type, so at most 64. The
                //   buffer has room for `MAX_FEATURES` (1024) strings
                //   whatever this or any earlier call returned, so no call
                //   sequence can make the kernel write past it. Soundness
                //   therefore relies on the kernel's NETDEV_FEATURE_COUNT
                //   being at most 1024 (today at most 64, since
                //   `netdev_features_t` is a `u64`).
                // - `ETHTOOL_GFEATURES` copies `min(size we pass,
                //   ETHTOOL_DEV_FEATURE_WORDS)` blocks, at most what the
                //   buffer holds.
                let result = unsafe {
                    ioctl(
                        self.fd.as_raw_fd(),
                        SIOCETHTOOL,
                        std::ptr::addr_of_mut!(request),
                    )
                };
                if result < 0 {
                    return Err(last_errno());
                }
                Ok(buffer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(names: &[&str]) -> Vec<u8> {
        let mut reply = strings_request();
        let len = u32::try_from(names.len()).unwrap();
        reply[8..12].copy_from_slice(&len.to_ne_bytes());
        for (index, name) in names.iter().enumerate() {
            let at = 12 + index * GSTRING_LEN;
            reply[at..at + name.len()].copy_from_slice(name.as_bytes());
        }
        reply
    }

    fn features(count: usize, active: &[usize]) -> Vec<u8> {
        let mut reply = features_request(feature_words(count)).unwrap();
        for bit in active {
            let offset = 8 + (bit / 32) * 16 + 8;
            let mut word = u32::from_ne_bytes(reply[offset..offset + 4].try_into().unwrap());
            word |= 1 << (bit % 32);
            reply[offset..offset + 4].copy_from_slice(&word.to_ne_bytes());
        }
        reply
    }

    #[test]
    fn requests_have_the_uapi_layout() {
        let info = Command::SsetInfo.buffer().unwrap();
        assert_eq!(info.len(), 20);
        assert_eq!(u32::from_ne_bytes(info[0..4].try_into().unwrap()), 0x37);
        assert_eq!(u64::from_ne_bytes(info[8..16].try_into().unwrap()), 16);
        let request = Command::Strings.buffer().unwrap();
        assert_eq!(request.len(), 12 + 1_024 * 32);
        assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 0x1b);
        assert_eq!(u32::from_ne_bytes(request[4..8].try_into().unwrap()), 4);
        assert_eq!(u32::from_ne_bytes(request[8..12].try_into().unwrap()), 0);
        let request = Command::Features { words: 3 }.buffer().unwrap();
        assert_eq!(request.len(), 8 + 48);
        // Sizes are checked: no empty or oversized command.
        for command in [
            Command::Features { words: 0 },
            Command::Features { words: 33 },
            Command::Features { words: usize::MAX },
        ] {
            assert_eq!(
                command.buffer(),
                Err(OffloadError::Malformed),
                "{command:?}"
            );
        }
        assert!(Command::Features { words: 32 }.buffer().is_ok());
        assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 0x3a);
        assert_eq!(u32::from_ne_bytes(request[4..8].try_into().unwrap()), 3);
        assert_eq!(feature_words(1), 1);
        assert_eq!(feature_words(32), 1);
        assert_eq!(feature_words(33), 2);
    }

    #[test]
    fn the_feature_count_must_be_answered_and_bounded() {
        let mut reply = sset_info_request();
        reply[16..20].copy_from_slice(&70_u32.to_ne_bytes());
        assert_eq!(sset_info_count(&reply), Ok(70));
        // The kernel cleared the mask: it does not know the set.
        let mut unknown = reply;
        unknown[8..16].copy_from_slice(&0_u64.to_ne_bytes());
        assert_eq!(sset_info_count(&unknown), Err(OffloadError::Malformed));
        for count in [0_u32, 1_025, u32::MAX] {
            let mut bad = reply;
            bad[16..20].copy_from_slice(&count.to_ne_bytes());
            assert_eq!(sset_info_count(&bad), Err(OffloadError::Malformed));
        }
    }

    #[test]
    fn active_offloads_are_found_by_name_in_any_word() {
        // Names at kernel-like positions: the bits differ between kernels.
        let mut names: Vec<String> = (0..70).map(|bit| format!("feature-{bit}")).collect();
        names[14] = "rx-gro".to_owned();
        names[15] = "rx-lro".to_owned();
        names[33] = "rx-gro-hw".to_owned();
        names[40] = "rx-gro-list".to_owned();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let strings = strings(&names);
        let count = names.len();
        assert_eq!(feature_bit(&strings, count, "rx-gro"), Ok(Some(14)));
        assert_eq!(feature_bit(&strings, count, "rx-gro-hw"), Ok(Some(33)));
        // A prefix is not the name.
        assert_eq!(feature_bit(&strings, count, "rx-gr"), Ok(None));
        assert_eq!(
            first_active(&strings, count, &features(count, &[])),
            Ok(None)
        );
        // Unchecked features (rx-gro-list, others) do not matter.
        assert_eq!(
            first_active(&strings, count, &features(count, &[0, 13, 16, 40, 69])),
            Ok(None)
        );
        for (bits, offload) in [
            (&[14][..], Offload::Gro),
            (&[15][..], Offload::Lro),
            (&[33][..], Offload::GroHw),
            (&[15, 33][..], Offload::Lro),
            (&[14, 15, 33][..], Offload::Gro),
        ] {
            assert_eq!(
                first_active(&strings, count, &features(count, bits)),
                Ok(Some(offload)),
                "{bits:?}"
            );
        }
        assert_eq!(Offload::GroHw.to_string(), "rx-gro-hw");
    }

    #[test]
    fn malformed_or_incomplete_replies_fail_closed() {
        let names = ["rx-gro", "rx-lro"];
        let strings = strings(&names);
        // rx-gro-hw is missing: unverifiable, not off.
        assert_eq!(
            first_active(&strings, 2, &features(2, &[])),
            Err(OffloadError::UnknownFeature(Offload::GroHw))
        );
        // A string reply of the wrong size or count.
        assert_eq!(
            feature_bit(&strings[..strings.len() - 1], 2, "rx-gro"),
            Err(OffloadError::Malformed)
        );
        for count in [0, MAX_FEATURES + 1, usize::MAX] {
            assert_eq!(
                feature_bit(&strings, count, "rx-gro"),
                Err(OffloadError::Malformed),
                "{count}"
            );
        }
        // Only the counted strings are read.
        assert_eq!(feature_bit(&strings, 2, "rx-lro"), Ok(Some(1)));
        let mut one = strings.clone();
        one[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(feature_bit(&one, 1, "rx-lro"), Ok(None));
        let mut miscounted = strings.clone();
        miscounted[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(
            feature_bit(&miscounted, 2, "rx-gro"),
            Err(OffloadError::Malformed)
        );
        // A feature reply too short for the bit.
        assert_eq!(
            feature_active(&features(32, &[]), 32),
            Err(OffloadError::Malformed)
        );
        assert_eq!(feature_active(&features(33, &[32]), 32), Ok(true));
        // A reply whose `size` does not cover the word is malformed, even
        // if the buffer holds it.
        let mut short = features(64, &[33]);
        short[4..8].copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(feature_active(&short, 33), Err(OffloadError::Malformed));
        assert_eq!(feature_active(&short, 3), Ok(false));
        // The kernel's larger word count is fine.
        let mut larger = features(33, &[32]);
        larger[4..8].copy_from_slice(&3_u32.to_ne_bytes());
        assert_eq!(feature_active(&larger, 32), Ok(true));
    }
}

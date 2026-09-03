//! Linux UDS control plane for the live daemon.
//!
//! This module intentionally follows `sd_notify.rs`: the small AF_UNIX
//! surface is implemented with the Linux socket ABI directly instead of
//! adding a dependency to the CLI.  The listener is owned by the daemon's
//! tick-loop thread, and every operation on a listener or accepted client is
//! non-blocking.

use std::{
    env, fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

pub(crate) const CONTROL_SOCKET_ENV: &str = "RUSTER_CONTROL_SOCKET";

const DEFAULT_CONTROL_SOCKET: &str = "/run/ruster/control.sock";

// Linux defines these values as part of the socket ABI.  Keeping the values
// beside the raw declarations makes the ABI boundary auditable in the same
// way as the AF_UNIX implementation in `sd_notify.rs`.
const AF_UNIX: std::ffi::c_int = 1;
const SOCK_STREAM: std::ffi::c_int = 1;
const SOCK_DGRAM: std::ffi::c_int = 2;
const SOCK_SEQPACKET: std::ffi::c_int = 5;
const SOCK_CLOEXEC: std::ffi::c_int = 0o2_000_000;
const SOCK_NONBLOCK: std::ffi::c_int = 0o4_000;
const SOL_SOCKET: std::ffi::c_int = 1;
const SO_PEERCRED: std::ffi::c_int = 17;
const SO_ERROR: std::ffi::c_int = 4;
const SCM_RIGHTS: std::ffi::c_int = 1;

const MSG_CTRUNC: std::ffi::c_int = 0x0008;
const MSG_TRUNC: std::ffi::c_int = 0x0020;
const MSG_NOSIGNAL: std::ffi::c_int = 0x4000;
const MSG_CMSG_CLOEXEC: std::ffi::c_int = 0x4000_0000;

const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EINPROGRESS: i32 = 115;
const EPIPE: i32 = 32;
const ECONNRESET: i32 = 104;
const ECONNREFUSED: i32 = 111;
const EALREADY: i32 = 114;
#[cfg(test)]
const EEXIST: i32 = 17;
const ENOENT: i32 = 2;

const SUN_PATH_LEN: usize = 108;
const SUN_PATH_OFFSET: usize = std::mem::size_of::<u16>();

// The socket inode is deliberately owner/group accessible and inaccessible
// to everyone else.  The daemon's effective uid/gid are also checked with
// SO_PEERCRED below; the mode is the kernel-side protection for the same
// owner/group policy and does not rely on the inherited umask.
const CONTROL_SOCKET_MODE: u32 = 0o660;

// Control messages are small and bounded.  A deliberately finite ancillary
// buffer also lets recvmsg report MSG_CTRUNC instead of accepting a partial
// control message.  Any received SCM_RIGHTS descriptors are closed below.
const MAX_REQUEST_BYTES: usize = 64;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const CONTROL_CMSG_BUFFER_BYTES: usize = 128;
const CONTROL_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
// Kept as a named ABI choice so the probe's nonblocking guarantee has a
// direct regression test alongside the socket implementation.
const CONTROL_PROBE_SOCKET_FLAGS: std::ffi::c_int = SOCK_NONBLOCK | SOCK_CLOEXEC;

const POLLOUT: std::ffi::c_short = 0x0004;
const POLLERR: std::ffi::c_short = 0x0008;
const POLLHUP: std::ffi::c_short = 0x0010;
const POLLNVAL: std::ffi::c_short = 0x0020;
const AT_FDCWD: std::ffi::c_int = -100;
const RENAME_NOREPLACE: std::ffi::c_uint = 1;
const O_DIRECTORY: std::ffi::c_int = 0o200_000;
const O_NOFOLLOW: std::ffi::c_int = 0o400_000;
const O_PATH: std::ffi::c_int = 0o10_000_000;

// A busy control client must not be able to starve packet forwarding or hold
// unbounded accepted descriptors.  New connections and complete requests are
// independently bounded per tick.
const MAX_PENDING_CLIENTS: usize = 64;
// listen(2) below uses MAX_PENDING_CLIENTS as its backlog.  At most 64
// rejected peers can be ahead of one authorized peer in that finite queue, so
// 65 accept4 calls cover the whole burst and its authorized tail in one tick.
// The explicit finite bound still returns control to the packet path, and
// rejected peers never consume a PendingClient slot.
const MAX_ACCEPTS_PER_TICK: usize = MAX_PENDING_CLIENTS + 1;
const MAX_REQUESTS_PER_TICK: usize = 8;
const CONTROL_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

static NEXT_CONTROL_TEMP: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; SUN_PATH_LEN],
}

#[repr(C)]
struct Iovec {
    iov_base: *mut std::ffi::c_void,
    iov_len: usize,
}

#[repr(C)]
struct MsgHdr {
    msg_name: *mut std::ffi::c_void,
    msg_namelen: u32,
    msg_iov: *mut Iovec,
    msg_iovlen: usize,
    msg_control: *mut std::ffi::c_void,
    msg_controllen: usize,
    msg_flags: std::ffi::c_int,
}

#[repr(C)]
struct PollFd {
    fd: std::ffi::c_int,
    events: std::ffi::c_short,
    revents: std::ffi::c_short,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CmsgHdr {
    cmsg_len: usize,
    cmsg_level: std::ffi::c_int,
    cmsg_type: std::ffi::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ucred {
    pid: std::ffi::c_int,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy)]
struct ControlAddress {
    sockaddr: SockAddrUn,
    length: u32,
}

impl ControlAddress {
    fn from_path(path: &Path) -> Result<Self, String> {
        Self::from_bytes(path.as_os_str().as_bytes())
    }

    fn from_bytes(value: &[u8]) -> Result<Self, String> {
        if value.is_empty() {
            return Err("control socket path must not be empty".to_owned());
        }
        if value.contains(&0) {
            return Err("control socket path contains an embedded NUL".to_owned());
        }
        // A pathname address needs one byte for the terminating NUL.  Do not
        // truncate: Linux bind(2) would otherwise address a different name.
        if value.len() >= SUN_PATH_LEN {
            return Err(format!(
                "control socket path is too long for Linux sun_path: {} bytes; maximum is {} bytes",
                value.len(),
                SUN_PATH_LEN - 1
            ));
        }

        let mut sockaddr = SockAddrUn {
            sun_family: AF_UNIX as u16,
            sun_path: [0; SUN_PATH_LEN],
        };
        sockaddr.sun_path[..value.len()].copy_from_slice(value);
        sockaddr.sun_path[value.len()] = 0;
        let length = SUN_PATH_OFFSET + value.len() + 1;
        Ok(Self {
            sockaddr,
            length: u32::try_from(length)
                .expect("Linux sockaddr_un pathname length fits in socklen_t"),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingSocketProbe {
    InUse,
    Stale,
}

fn control_socket_path() -> Result<PathBuf, String> {
    let path = env::var_os(CONTROL_SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));
    ControlAddress::from_path(&path)?;
    Ok(path)
}

struct SecureSocketPath {
    path: PathBuf,
    file_name: Vec<u8>,
    parent_fd: fs::File,
}

fn secure_socket_path(path: &Path) -> Result<SecureSocketPath, String> {
    let file_name = path.file_name().ok_or_else(|| {
        format!("control socket path {path:?} must name a socket below a parent directory")
    })?;
    let file_name = file_name.as_bytes();
    if matches!(file_name, b"." | b"..") {
        return Err(format!(
            "control socket path {path:?} must name a socket below a parent directory"
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).map_err(|error| {
        format!("cannot resolve control socket parent directory {parent:?}: {error}")
    })?;

    // SAFETY: geteuid has no pointer arguments and returns this process's
    // effective uid for the complete ancestor ownership check.
    let daemon_uid = unsafe { geteuid() };
    let expected_parent = validate_trusted_ancestors(&canonical_parent, daemon_uid)?;
    // The temporary bind, pathname chmod, and dirfd-pinned publication and
    // cleanup below are safe only after every canonical ancestor is trusted
    // and an attacker cannot replace descendants through its permissions.
    let parent_fd = open_directory_fd(&canonical_parent)?;
    let opened_parent = parent_fd.metadata().map_err(|error| {
        format!(
            "cannot inspect pinned control socket parent directory {canonical_parent:?}: {error}"
        )
    })?;
    if SocketIdentity::from_metadata(&opened_parent)
        != SocketIdentity::from_metadata(&expected_parent)
    {
        return Err(format!(
            "control socket parent directory {canonical_parent:?} changed while being pinned; refusing to bind"
        ));
    }

    let secured_path = canonical_parent.join(std::ffi::OsString::from_vec(file_name.to_vec()));
    ControlAddress::from_path(&secured_path)?;
    Ok(SecureSocketPath {
        path: secured_path,
        file_name: file_name.to_vec(),
        parent_fd,
    })
}

fn validate_trusted_ancestors(
    canonical_parent: &Path,
    daemon_uid: u32,
) -> Result<fs::Metadata, String> {
    let mut parent_metadata = None;
    for ancestor in canonical_parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            format!("cannot inspect control socket ancestor directory {ancestor:?}: {error}")
        })?;
        let descriptor = if ancestor == canonical_parent {
            "parent directory"
        } else {
            "ancestor directory"
        };
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "control socket {descriptor} path {ancestor:?} is not a directory; refusing to bind"
            ));
        }
        let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == daemon_uid;
        let mode = metadata.mode() & 0o7777;
        let is_group_or_other_writable = mode & 0o022 != 0;
        if !owner_is_trusted {
            return Err(format!(
                "control socket {descriptor} {ancestor:?} is owned by uid {}; refusing to bind",
                metadata.uid()
            ));
        }
        if ancestor == canonical_parent {
            if is_group_or_other_writable {
                return Err(format!(
                    "control socket {descriptor} {ancestor:?} is group/other-writable (mode {:04o}); refusing to bind",
                    mode
                ));
            }
        } else if is_group_or_other_writable && mode & 0o1000 == 0 {
            return Err(format!(
                "control socket {descriptor} {ancestor:?} is group/other-writable (mode {:04o}); refusing to bind",
                mode
            ));
        }
        if ancestor == canonical_parent {
            parent_metadata = Some(metadata);
        }
    }
    parent_metadata.ok_or_else(|| {
        format!(
            "control socket parent directory {canonical_parent:?} could not be validated; refusing to bind"
        )
    })
}

fn open_directory_fd(path: &Path) -> Result<fs::File, String> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "control socket parent path contains an embedded NUL",
            )
        })
        .map_err(|error| error.to_string())?;
    // SAFETY: `path` is a live NUL-terminated pathname, the flags request a
    // directory fd without following a final symlink, and the call does not
    // retain any Rust pointer after returning.
    let fd = unsafe {
        openat(
            AT_FDCWD,
            path.as_ptr(),
            O_DIRECTORY | O_NOFOLLOW | SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(format!(
            "cannot pin control socket parent directory: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` was returned by openat above and is transferred exactly
    // once into the owning File.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn metadata_at(directory_fd: RawFd, name: &[u8]) -> io::Result<fs::Metadata> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component has NUL"))?;
    // SAFETY: `name` is a live NUL-terminated component, and the flags return
    // an fd for the named inode without following a final symlink.
    let fd = unsafe {
        openat(
            directory_fd,
            name.as_ptr(),
            O_PATH | O_NOFOLLOW | SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by openat above and is transferred exactly
    // once into the temporary owning File.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    file.metadata()
}

fn unlink_at(directory_fd: RawFd, name: &[u8]) -> io::Result<()> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component has NUL"))?;
    // SAFETY: `name` is a live NUL-terminated component, directory_fd pins
    // the intended parent, and unlinkat does not follow a final symlink.
    let result = unsafe { unlinkat(directory_fd, name.as_ptr(), 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn temporary_socket_path(parent_fd: RawFd, path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("control socket path {path:?} has no parent directory"))?;
    let parent_length = parent.as_os_str().as_bytes().len();
    let available_name_length = SUN_PATH_LEN
        .checked_sub(1)
        .and_then(|length| length.checked_sub(parent_length + 1))
        .ok_or_else(|| {
            format!(
                "control socket parent directory {parent:?} leaves no room for a safe temporary socket name"
            )
        })?;
    if available_name_length < 2 {
        return Err(format!(
            "control socket parent directory {parent:?} leaves no unique temporary socket name"
        ));
    }

    for _ in 0..32 {
        let sequence = NEXT_CONTROL_TEMP.fetch_add(1, Ordering::Relaxed);
        let candidate_name = format!(".ruster-control-{:x}-{:x}", std::process::id(), sequence);
        if candidate_name.len() > available_name_length {
            return Err(format!(
                "control socket parent directory {parent:?} leaves insufficient pathname space for safe publication"
            ));
        }
        let candidate = parent.join(candidate_name);
        match metadata_at(parent_fd, candidate.file_name().unwrap().as_bytes()) {
            Ok(_) => continue,
            Err(error) if error.raw_os_error() == Some(ENOENT) => return Ok(candidate),
            Err(error) => {
                return Err(format!(
                    "cannot inspect temporary control socket path {candidate:?}: {error}"
                ));
            }
        }
    }
    Err(format!(
        "cannot allocate a collision-free temporary control socket path below {parent:?}"
    ))
}

fn socket_mode_at(directory_fd: RawFd, name: &[u8], path: &Path) -> Result<u32, String> {
    let metadata = metadata_at(directory_fd, name)
        .map_err(|error| format!("cannot inspect control socket path {path:?}: {error}"))?;
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "control socket path {path:?} is not a socket while checking its mode"
        ));
    }
    Ok(metadata.mode() & 0o7777)
}

fn socket_identity_at(
    directory_fd: RawFd,
    name: &[u8],
    path: &Path,
) -> Result<SocketIdentity, String> {
    let metadata = metadata_at(directory_fd, name)
        .map_err(|error| format!("cannot inspect bound control socket path {path:?}: {error}"))?;
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "bound control socket path {path:?} is not a socket"
        ));
    }
    Ok(SocketIdentity::from_metadata(&metadata))
}

fn remove_socket_if_identity_at(
    directory_fd: RawFd,
    path: &Path,
    file_name: &[u8],
    identity: SocketIdentity,
) {
    let metadata = match metadata_at(directory_fd, file_name) {
        Ok(metadata) => metadata,
        Err(error) if error.raw_os_error() == Some(ENOENT) => return,
        Err(error) => {
            eprintln!(
                "ruster: cannot inspect control socket path {path:?} during cleanup: {error}"
            );
            return;
        }
    };
    if !metadata.file_type().is_socket() {
        eprintln!(
            "ruster: control socket path {path:?} changed to a non-socket; refusing to unlink it"
        );
        return;
    }
    if SocketIdentity::from_metadata(&metadata) != identity {
        eprintln!(
            "ruster: control socket path {path:?} changed to another socket; refusing to unlink it"
        );
        return;
    }
    if let Err(error) = unlink_at(directory_fd, file_name) {
        if error.raw_os_error() != Some(ENOENT) {
            eprintln!("ruster: cannot unlink control socket path {path:?}: {error}");
        }
    }
}

#[cfg(test)]
fn publish_socket_path(temporary_path: &Path, path: &Path) -> io::Result<()> {
    let temporary_path = std::ffi::CString::new(temporary_path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "temporary path has NUL"))?;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "control path has NUL"))?;
    // RENAME_NOREPLACE makes a pathname symlink inserted after prepare/bind
    // an ordinary publication failure.  rename(2) does not follow the final
    // symlink, and this flag additionally prevents overwriting a replacement
    // socket or file.
    // SAFETY: both CStrings are NUL-terminated live paths, AT_FDCWD selects
    // the process cwd for the absolute paths, and renameat2 copies no Rust
    // references beyond this call.
    let result = unsafe {
        renameat2(
            AT_FDCWD,
            temporary_path.as_ptr(),
            AT_FDCWD,
            path.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn publish_socket_path_at(
    parent_fd: RawFd,
    temporary_name: &[u8],
    file_name: &[u8],
) -> io::Result<()> {
    let temporary_name = std::ffi::CString::new(temporary_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "temporary path has NUL"))?;
    let file_name = std::ffi::CString::new(file_name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "control path has NUL"))?;
    // RENAME_NOREPLACE performs the final publication against the pinned
    // parent directory.  It cannot follow or overwrite a final pathname
    // symlink inserted after the earlier stale-path checks.
    // SAFETY: both names are live NUL-terminated single components,
    // parent_fd remains open for the duration of the call, and renameat2 does
    // not retain either Rust pointer after returning.
    let result = unsafe {
        renameat2(
            parent_fd,
            temporary_name.as_ptr(),
            parent_fd,
            file_name.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn prepare_socket_path(
    parent_fd: RawFd,
    file_name: &[u8],
    path: &Path,
    address: ControlAddress,
) -> Result<(), String> {
    let metadata = match metadata_at(parent_fd, file_name) {
        Ok(metadata) => metadata,
        Err(error) if error.raw_os_error() == Some(ENOENT) => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect control socket path {path:?}: {error}"
            ));
        }
    };

    if !metadata.file_type().is_socket() {
        return Err(format!(
            "control socket path {path:?} already exists and is not a socket; refusing to unlink it"
        ));
    }
    let original_identity = SocketIdentity::from_metadata(&metadata);

    match probe_existing_socket(address) {
        Ok(ExistingSocketProbe::InUse) => Err(format!(
            "control socket path {path:?} is already in use; refusing to unlink it"
        )),
        Ok(ExistingSocketProbe::Stale) => {
            // Re-check both type and identity after the probe.  This avoids
            // unlinking a path that was replaced while the probe was running.
            match metadata_at(parent_fd, file_name) {
                Ok(current) if current.file_type().is_socket() => {
                    let current_identity = SocketIdentity::from_metadata(&current);
                    if current_identity != original_identity {
                        return Err(format!(
                            "control socket path {path:?} changed while probing; refusing to unlink it"
                        ));
                    }
                }
                Ok(_) => {
                    return Err(format!(
                        "control socket path {path:?} changed to a non-socket while probing; refusing to unlink it"
                    ));
                }
                Err(error) if error.raw_os_error() == Some(ENOENT) => return Ok(()),
                Err(error) => {
                    return Err(format!(
                        "cannot re-check stale control socket path {path:?}: {error}"
                    ));
                }
            }

            match unlink_at(parent_fd, file_name) {
                Ok(()) => {
                    eprintln!(
                        "ruster: removed stale control socket path {path:?} after a refused connect probe"
                    );
                    Ok(())
                }
                Err(error) if error.raw_os_error() == Some(ENOENT) => Ok(()),
                Err(error) => Err(format!(
                    "cannot remove stale control socket path {path:?}: {error}"
                )),
            }
        }
        Err(error) => Err(format!(
            "cannot probe existing control socket path {path:?}; refusing to unlink it: {error}"
        )),
    }
}

enum ConnectProbeOutcome {
    Connected,
    Refused,
    Conservative(io::Error),
    Failed(io::Error),
}

fn probe_existing_socket(address: ControlAddress) -> io::Result<ExistingSocketProbe> {
    // A matching seqpacket endpoint is the normal case.  The stream and
    // datagram probes prevent us from mistaking a live socket of another
    // AF_UNIX type for a stale seqpacket pathname.
    match connect_probe_outcome(address, SOCK_SEQPACKET, crate::stop_requested) {
        ConnectProbeOutcome::Connected => return Ok(ExistingSocketProbe::InUse),
        ConnectProbeOutcome::Refused => {}
        ConnectProbeOutcome::Conservative(error) => {
            // A timeout, poll failure, SO_ERROR failure, or stop request is
            // deliberately treated as live/in-use.  None of these uncertain
            // outcomes may authorize stale pathname removal.
            eprintln!("ruster: control socket probe was inconclusive; retaining path: {error}");
            return Ok(ExistingSocketProbe::InUse);
        }
        ConnectProbeOutcome::Failed(error) => return Err(error),
    }

    for socket_type in [SOCK_STREAM, SOCK_DGRAM] {
        match connect_probe_outcome(address, socket_type, crate::stop_requested) {
            ConnectProbeOutcome::Connected => return Ok(ExistingSocketProbe::InUse),
            ConnectProbeOutcome::Refused => {}
            ConnectProbeOutcome::Conservative(error) => {
                eprintln!("ruster: control socket probe was inconclusive; retaining path: {error}");
                return Ok(ExistingSocketProbe::InUse);
            }
            ConnectProbeOutcome::Failed(error) => return Err(error),
        }
    }

    // For each supported local socket type, ECONNREFUSED means there is no
    // accepting endpoint at this pathname.  Only this conservative result is
    // allowed to lead to unlink; permission, protocol, resource, and other
    // errors fail closed above.
    Ok(ExistingSocketProbe::Stale)
}

#[cfg(test)]
fn connect_probe(address: ControlAddress, socket_type: std::ffi::c_int) -> io::Result<()> {
    match connect_probe_outcome(address, socket_type, crate::stop_requested) {
        ConnectProbeOutcome::Connected => Ok(()),
        ConnectProbeOutcome::Refused => Err(io::Error::from_raw_os_error(ECONNREFUSED)),
        ConnectProbeOutcome::Conservative(error) | ConnectProbeOutcome::Failed(error) => Err(error),
    }
}

fn connect_probe_outcome(
    address: ControlAddress,
    socket_type: std::ffi::c_int,
    stop_requested: impl Fn() -> bool,
) -> ConnectProbeOutcome {
    // A probe must never hold startup on a live endpoint with a full queue.
    // SOCK_NONBLOCK bounds connect(2); SOCK_CLOEXEC preserves the descriptor
    // leak protection used by the rest of this module.
    // SAFETY: the constants select a Linux AF_UNIX probe socket and no Rust
    // pointer is passed to socket(2).
    let fd = unsafe { socket(AF_UNIX, socket_type | CONTROL_PROBE_SOCKET_FLAGS, 0) };
    if fd < 0 {
        return ConnectProbeOutcome::Failed(io::Error::last_os_error());
    }

    // The deadline starts before the first connect(2), not only when an
    // EINPROGRESS result enters poll(2).  A signal can interrupt a
    // nonblocking connect repeatedly, so the EINTR retry loop must consume
    // this same finite budget.
    let deadline = Instant::now()
        .checked_add(CONTROL_PROBE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let result = loop {
        if stop_requested() {
            break ConnectProbeOutcome::Conservative(io::Error::new(
                io::ErrorKind::Interrupted,
                "control socket probe stopped before connect",
            ));
        }
        if Instant::now() >= deadline {
            break ConnectProbeOutcome::Conservative(io::Error::new(
                io::ErrorKind::TimedOut,
                "control socket probe connect timed out before connect",
            ));
        }

        // SAFETY: `address` is a live, initialized sockaddr_un and its length
        // includes exactly the pathname plus its terminating NUL.
        let connected = unsafe { connect(fd, &address.sockaddr, address.length) };
        if connected == 0 {
            if stop_requested() || Instant::now() >= deadline {
                break ConnectProbeOutcome::Conservative(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control socket probe connect completed after its deadline",
                ));
            }
            break ConnectProbeOutcome::Connected;
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(EINTR) => {
                // The loop header checks both stop and deadline before every
                // retry.  Either condition is conservative: it never proves
                // that a pathname is stale and therefore never authorizes
                // unlinking it.
                continue;
            }
            Some(EINPROGRESS) | Some(EALREADY) => {
                break wait_for_probe_connect(fd, deadline, stop_requested);
            }
            Some(ECONNREFUSED) => break ConnectProbeOutcome::Refused,
            Some(EAGAIN) => break ConnectProbeOutcome::Conservative(error),
            _ => break ConnectProbeOutcome::Failed(error),
        }
    };
    // SAFETY: `fd` was returned by socket above and is owned by this probe.
    let _ = unsafe { close(fd) };
    result
}

fn wait_for_probe_connect(
    fd: RawFd,
    deadline: Instant,
    stop_requested: impl Fn() -> bool,
) -> ConnectProbeOutcome {
    loop {
        if stop_requested() {
            return ConnectProbeOutcome::Conservative(io::Error::new(
                io::ErrorKind::Interrupted,
                "control socket probe stopped while waiting for connect",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return ConnectProbeOutcome::Conservative(io::Error::new(
                io::ErrorKind::TimedOut,
                "control socket probe connect timed out",
            ));
        }
        let mut poll_fd = PollFd {
            fd,
            events: POLLOUT,
            revents: 0,
        };
        let timeout_ms = poll_timeout_millis(remaining);
        // SAFETY: poll_fd points to one initialized pollfd for this call and
        // the timeout is finite; poll never retains the pointer.
        let polled = unsafe { poll(&mut poll_fd, 1, timeout_ms) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(EINTR) {
                // Retry EINTR only while the stop flag is clear.  This check
                // makes shutdown responsive without treating an interrupted
                // wait as evidence that the pathname is stale.
                if stop_requested() {
                    return ConnectProbeOutcome::Conservative(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "control socket probe stopped after poll EINTR",
                    ));
                }
                continue;
            }
            return ConnectProbeOutcome::Conservative(error);
        }
        if polled == 0 {
            return ConnectProbeOutcome::Conservative(io::Error::new(
                io::ErrorKind::TimedOut,
                "control socket probe poll timed out",
            ));
        }
        if poll_fd.revents & POLLNVAL != 0 {
            return ConnectProbeOutcome::Conservative(io::Error::other(
                "control socket probe poll reported an invalid descriptor",
            ));
        }
        if poll_fd.revents & (POLLOUT | POLLERR | POLLHUP) == 0 {
            continue;
        }

        let mut socket_error: std::ffi::c_int = 0;
        let mut length =
            u32::try_from(std::mem::size_of_val(&socket_error)).expect("SO_ERROR size fits");
        // SAFETY: socket_error and length are writable buffers of the exact
        // SO_ERROR ABI shape, and fd remains owned by this probe.
        let result = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                (&mut socket_error as *mut std::ffi::c_int).cast(),
                &mut length,
            )
        };
        if result < 0 {
            return ConnectProbeOutcome::Conservative(io::Error::last_os_error());
        }
        if usize::try_from(length).unwrap_or(0) < std::mem::size_of_val(&socket_error) {
            return ConnectProbeOutcome::Conservative(io::Error::new(
                io::ErrorKind::InvalidData,
                "SO_ERROR returned a short value",
            ));
        }
        if socket_error == 0 {
            return ConnectProbeOutcome::Connected;
        }
        if socket_error == ECONNREFUSED {
            return ConnectProbeOutcome::Refused;
        }
        return ConnectProbeOutcome::Failed(io::Error::from_raw_os_error(socket_error));
    }
}

fn poll_timeout_millis(remaining: Duration) -> std::ffi::c_int {
    let millis = remaining
        .as_millis()
        .saturating_add(1)
        .min(i32::MAX as u128);
    i32::try_from(millis).unwrap_or(i32::MAX).max(1)
}

pub(crate) struct ControlListener {
    fd: RawFd,
    path: PathBuf,
    file_name: Vec<u8>,
    parent_fd: fs::File,
    identity: SocketIdentity,
    daemon_uid: u32,
    daemon_gid: u32,
    clients: Vec<PendingClient>,
}

struct PendingClient {
    fd: RawFd,
    accepted_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ControlProcessResult {
    pub(crate) requests_seen: usize,
    pub(crate) reload_requested: bool,
}

impl ControlListener {
    pub(crate) fn open() -> Result<Self, String> {
        let path = control_socket_path()?;
        Self::bind_path(&path)
    }

    // This path-specific constructor is also used by unit tests so they can
    // exercise the actual bind/probe/mode/listen sequence without relying on
    // the system-wide /run directory.
    pub(crate) fn bind_path(path: &Path) -> Result<Self, String> {
        ControlAddress::from_path(path)?;
        let SecureSocketPath {
            path,
            file_name,
            parent_fd,
        } = secure_socket_path(path)?;
        let parent_fd_raw = parent_fd.as_raw_fd();
        let address = ControlAddress::from_path(&path)?;
        prepare_socket_path(parent_fd_raw, &file_name, &path, address)?;
        let temporary_path = temporary_socket_path(parent_fd_raw, &path)?;
        let temporary_name = temporary_path
            .file_name()
            .expect("temporary socket path must have a file name")
            .as_bytes()
            .to_vec();
        let temporary_address = ControlAddress::from_path(&temporary_path)?;

        // SAFETY: `socket(2)` receives only scalar ABI arguments here; the
        // constants select an AF_UNIX SOCK_SEQPACKET listener with nonblocking
        // and close-on-exec status, and the returned fd is owned below.
        let fd = unsafe { socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(format!(
                "cannot create control socket {path:?}: {}",
                io::Error::last_os_error()
            ));
        }

        // SAFETY: `temporary_address` is initialized by the checked pathname
        // parser and remains alive for this bind call; `fd` is the socket just
        // created.
        if unsafe { control_bind(fd, &temporary_address.sockaddr, temporary_address.length) } < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: this fd is owned by the failed listener construction.
            let _ = unsafe { close(fd) };
            return Err(format!(
                "cannot bind temporary control socket path {temporary_path:?}: {error}"
            ));
        }

        let identity = match socket_identity_at(parent_fd_raw, &temporary_name, &temporary_path) {
            Ok(identity) => identity,
            Err(error) => {
                // SAFETY: this fd is owned by the failed listener construction.
                let _ = unsafe { close(fd) };
                remove_socket_if_identity_at(
                    parent_fd_raw,
                    &temporary_path,
                    &temporary_name,
                    SocketIdentity {
                        device: 0,
                        inode: 0,
                    },
                );
                return Err(error);
            }
        };

        // Linux applies the process umask while bind(2) creates a pathname
        // socket.  fchmod(2) on this AF_UNIX socket fd does not change the
        // pathname inode mode, so using fchmod alone would leave clients with
        // the umask-derived mode.  The parent directory was verified above;
        // set_permissions therefore operates on the private temporary name,
        // before that name is atomically published at the requested path.
        // Read the socket pathname's mode both before and after chmod so the
        // postcondition is about the inode clients will actually observe.
        let mode_before = match socket_mode_at(parent_fd_raw, &temporary_name, &temporary_path) {
            Ok(mode) => mode,
            Err(error) => {
                // SAFETY: this fd is owned by the failed listener construction.
                let _ = unsafe { close(fd) };
                remove_socket_if_identity_at(
                    parent_fd_raw,
                    &temporary_path,
                    &temporary_name,
                    identity,
                );
                return Err(error);
            }
        };
        if let Err(error) = fs::set_permissions(
            &temporary_path,
            fs::Permissions::from_mode(CONTROL_SOCKET_MODE),
        ) {
            // SAFETY: this fd is owned by the failed listener construction.
            let _ = unsafe { close(fd) };
            remove_socket_if_identity_at(parent_fd_raw, &temporary_path, &temporary_name, identity);
            return Err(format!(
                "cannot set control socket mode to 0660 for {path:?} (temporary mode was {mode_before:04o}): {error}"
            ));
        }
        let mode_after = match socket_mode_at(parent_fd_raw, &temporary_name, &temporary_path) {
            Ok(mode) => mode,
            Err(error) => {
                // SAFETY: this fd is owned by the failed listener construction.
                let _ = unsafe { close(fd) };
                remove_socket_if_identity_at(
                    parent_fd_raw,
                    &temporary_path,
                    &temporary_name,
                    identity,
                );
                return Err(error);
            }
        };
        if mode_after & 0o777 != CONTROL_SOCKET_MODE {
            // SAFETY: this fd is owned by the failed listener construction.
            let _ = unsafe { close(fd) };
            remove_socket_if_identity_at(parent_fd_raw, &temporary_path, &temporary_name, identity);
            return Err(format!(
                "control socket mode postcondition failed for {path:?}: before={mode_before:04o}, after={mode_after:04o}, expected {:04o}",
                CONTROL_SOCKET_MODE
            ));
        }

        // SAFETY: `fd` is the bound AF_UNIX socket and the backlog is finite.
        if unsafe { listen(fd, MAX_PENDING_CLIENTS as std::ffi::c_int) } < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: this fd is owned by the failed listener construction.
            let _ = unsafe { close(fd) };
            remove_socket_if_identity_at(parent_fd_raw, &temporary_path, &temporary_name, identity);
            return Err(format!(
                "cannot listen on control socket path {path:?}: {error}"
            ));
        }

        if let Err(error) = publish_socket_path_at(parent_fd_raw, &temporary_name, &file_name) {
            // SAFETY: this fd is owned by the failed listener construction.
            let _ = unsafe { close(fd) };
            remove_socket_if_identity_at(parent_fd_raw, &temporary_path, &temporary_name, identity);
            return Err(format!(
                "cannot publish control socket path {path:?} without replacing an existing path: {error}"
            ));
        }

        let published_identity = match socket_identity_at(parent_fd_raw, &file_name, &path) {
            Ok(identity) => identity,
            Err(error) => {
                // SAFETY: this fd is owned by the failed listener construction.
                let _ = unsafe { close(fd) };
                remove_socket_if_identity_at(parent_fd_raw, &path, &file_name, identity);
                return Err(error);
            }
        };
        if published_identity != identity {
            // SAFETY: this fd is owned by the failed listener construction.
            let _ = unsafe { close(fd) };
            remove_socket_if_identity_at(parent_fd_raw, &path, &file_name, identity);
            return Err(format!(
                "control socket path {path:?} changed during publication; refusing to keep it"
            ));
        }

        // SO_PEERCRED is compared with the daemon's effective identity.  That
        // is also the identity that owns the socket inode under the systemd
        // unit's User=/Group= settings.
        // SAFETY: `geteuid(2)` has no pointer arguments and returns the
        // current process's effective uid as a scalar value.
        let daemon_uid = unsafe { geteuid() };
        // SAFETY: `getegid(2)` has no pointer arguments and returns the
        // current process's effective gid as a scalar value.
        let daemon_gid = unsafe { getegid() };
        Ok(Self {
            fd,
            path,
            file_name,
            parent_fd,
            identity,
            daemon_uid,
            daemon_gid,
            clients: Vec::with_capacity(MAX_PENDING_CLIENTS),
        })
    }

    /// Services at most eight complete control requests per tick.  Accepted
    /// sockets remain queued when their peer has connected but has not sent a
    /// packet yet; both accept and recvmsg are non-blocking, so this method
    /// never turns control-plane activity into a tick-loop wait.
    pub(crate) fn process<F>(&mut self, mut status_line: F) -> ControlProcessResult
    where
        F: FnMut() -> String,
    {
        self.accept_connections();

        let mut result = ControlProcessResult::default();
        let mut index = 0;
        while index < self.clients.len() && result.requests_seen < MAX_REQUESTS_PER_TICK {
            match receive_request(self.clients[index].fd) {
                ControlReceive::NoMessage => {
                    if self.clients[index].accepted_at.elapsed() >= CONTROL_CLIENT_TIMEOUT {
                        eprintln!(
                            "ruster: closing idle control connection after {} seconds",
                            CONTROL_CLIENT_TIMEOUT.as_secs()
                        );
                        self.remove_client(index);
                    } else {
                        index += 1;
                    }
                }
                ControlReceive::Closed => self.remove_client(index),
                ControlReceive::ReceiveError(error) => {
                    if !is_peer_disconnect(&error) {
                        eprintln!(
                            "ruster: closing control connection after recvmsg error: {error}"
                        );
                    }
                    self.remove_client(index);
                }
                ControlReceive::Rejected(reason) => {
                    result.requests_seen += 1;
                    eprintln!("ruster: rejected control request: {reason}");
                    self.remove_client(index);
                }
                ControlReceive::Command(command) => {
                    result.requests_seen += 1;
                    match command {
                        ControlCommand::Status => {
                            let response = status_line();
                            if response.len() > MAX_RESPONSE_BYTES {
                                eprintln!(
                                    "ruster: refusing oversized status response: {} bytes (maximum {})",
                                    response.len(),
                                    MAX_RESPONSE_BYTES
                                );
                            } else if let Err(error) =
                                send_response(self.clients[index].fd, response.as_bytes())
                            {
                                if !is_peer_disconnect(&error) {
                                    eprintln!("ruster: control status response failed: {error}");
                                }
                            }
                        }
                        ControlCommand::Reload => {
                            // The main loop turns this result into the same
                            // RELOAD_REQUESTED atomic used by SIGHUP.  This
                            // module never duplicates reload preparation or
                            // publication logic.
                            result.reload_requested = true;
                            if let Err(error) =
                                send_response(self.clients[index].fd, b"reload requested")
                            {
                                if !is_peer_disconnect(&error) {
                                    eprintln!("ruster: control reload response failed: {error}");
                                }
                            }
                        }
                        ControlCommand::Invalid => {
                            eprintln!("ruster: rejected unknown control command");
                        }
                    }
                    self.remove_client(index);
                }
            }
        }
        result
    }

    fn accept_connections(&mut self) {
        let mut attempts = 0;
        while attempts < MAX_ACCEPTS_PER_TICK {
            attempts += 1;
            // SAFETY: null address pointers ask accept4 not to return the
            // peer address.  The flags make every accepted fd non-blocking
            // and close-on-exec before it is exposed to this process.
            let fd = unsafe {
                accept4(
                    self.fd,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    SOCK_NONBLOCK | SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(EAGAIN) => break,
                    Some(EINTR) => continue,
                    _ => {
                        eprintln!("ruster: control accept4 failed: {error}");
                        break;
                    }
                }
            }

            if self.clients.len() >= MAX_PENDING_CLIENTS {
                eprintln!(
                    "ruster: rejecting control connection because {} clients are already pending",
                    MAX_PENDING_CLIENTS
                );
                // SAFETY: `fd` was returned by accept4 and is rejected here.
                let _ = unsafe { close(fd) };
                continue;
            }

            let credentials = match peer_credentials(fd) {
                Ok(credentials) => credentials,
                Err(error) => {
                    eprintln!(
                        "ruster: rejecting control connection without peer credentials: {error}"
                    );
                    // SAFETY: `fd` was returned by accept4 and is rejected here.
                    let _ = unsafe { close(fd) };
                    continue;
                }
            };
            if !peer_is_authorized(
                credentials.uid,
                credentials.gid,
                self.daemon_uid,
                self.daemon_gid,
            ) {
                // SO_PEERCRED exposes only the peer's uid and primary gid;
                // supplementary groups are intentionally not treated as an
                // authorization signal.  This keeps the rule auditable and
                // matches the 0660 owner/primary-group socket policy.
                eprintln!(
                    "ruster: rejected unauthorized control connection uid={} gid={}; authorization requires uid 0, daemon uid {}, or daemon primary gid {} (supplementary groups are not accepted)",
                    credentials.uid,
                    credentials.gid,
                    self.daemon_uid,
                    self.daemon_gid
                );
                // No response is sent to an unauthorized peer, so it receives
                // no daemon state or error details beyond a closed connection.
                // SAFETY: `fd` was returned by accept4 and is rejected here.
                let _ = unsafe { close(fd) };
                continue;
            }

            self.clients.push(PendingClient {
                fd,
                accepted_at: Instant::now(),
            });
        }
    }

    fn remove_client(&mut self, index: usize) {
        let client = self.clients.swap_remove(index);
        // SAFETY: every PendingClient fd came from accept4 and is owned here.
        let _ = unsafe { close(client.fd) };
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        for client in self.clients.drain(..) {
            // SAFETY: every PendingClient fd came from accept4 and is owned here.
            let _ = unsafe { close(client.fd) };
        }
        // Closing the listener before unlinking makes the pathname disappear
        // only after no daemon fd can accept another request.
        // SAFETY: `fd` was created and is owned by this listener.
        let _ = unsafe { close(self.fd) };
        remove_socket_if_identity_at(
            self.parent_fd.as_raw_fd(),
            &self.path,
            &self.file_name,
            self.identity,
        );
    }
}

#[cfg(test)]
fn socket_identity(path: &Path) -> Result<SocketIdentity, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect bound control socket path {path:?}: {error}"))?;
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "bound control socket path {path:?} is not a socket"
        ));
    }
    Ok(SocketIdentity::from_metadata(&metadata))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerCredentials {
    uid: u32,
    gid: u32,
}

fn peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut credentials = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length =
        u32::try_from(std::mem::size_of::<Ucred>()).expect("Linux ucred size fits in socklen_t");
    // SAFETY: `credentials` and `length` are writable buffers of their exact
    // ABI sizes, and fd is a live accepted AF_UNIX socket.
    let result = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credentials as *mut Ucred).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).unwrap_or(0) < std::mem::size_of::<Ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_PEERCRED returned a short ucred structure",
        ));
    }
    Ok(PeerCredentials {
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

/// Returns whether a peer may use the control plane.
///
/// Root is allowed for operational recovery.  The daemon's own uid is
/// allowed so a rootless `ruster status` from the service account works, and
/// the daemon's primary gid is allowed for explicitly configured operators.
/// SO_PEERCRED supplies one uid/gid pair, not supplementary groups, so callers
/// must not interpret a supplementary group as satisfying this predicate.
pub(crate) const fn peer_is_authorized(
    peer_uid: u32,
    peer_gid: u32,
    daemon_uid: u32,
    daemon_gid: u32,
) -> bool {
    peer_uid == 0 || peer_uid == daemon_uid || peer_gid == daemon_gid
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlCommand {
    Status,
    Reload,
    Invalid,
}

enum ControlReceive {
    NoMessage,
    Closed,
    Rejected(&'static str),
    Command(ControlCommand),
    ReceiveError(io::Error),
}

fn receive_request(fd: RawFd) -> ControlReceive {
    let mut payload = [0_u8; MAX_REQUEST_BYTES];
    let mut control = [0_u8; CONTROL_CMSG_BUFFER_BYTES];
    let mut iovec = Iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message = MsgHdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iovec,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };

    // accepted fd is SOCK_NONBLOCK, so recvmsg cannot wait for a client that
    // connected without sending yet.  EINTR retains the client for the next
    // tick; no packet has been consumed in that case.
    // SAFETY: all pointers in MsgHdr refer to live buffers for this call, and
    // MSG_CMSG_CLOEXEC marks any received SCM_RIGHTS fd close-on-exec.
    let length = unsafe { recvmsg(fd, &mut message, MSG_CMSG_CLOEXEC) };
    if length < 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(EAGAIN | EINTR)) {
            return ControlReceive::NoMessage;
        }
        return ControlReceive::ReceiveError(error);
    }

    let control_length = message.msg_controllen.min(control.len());
    // MSG_CMSG_CLOEXEC prevents an exec-time leak, while this pass closes any
    // SCM_RIGHTS descriptors immediately because the control plane never
    // accepts or uses passed fds.
    close_received_fds(&control[..control_length]);

    if message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) != 0 {
        let reason = match message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) {
            flags if flags == (MSG_TRUNC | MSG_CTRUNC) => "MSG_TRUNC and MSG_CTRUNC",
            flags if flags == MSG_TRUNC => "MSG_TRUNC",
            _ => "MSG_CTRUNC",
        };
        return ControlReceive::Rejected(reason);
    }

    let Ok(length) = usize::try_from(length) else {
        return ControlReceive::Rejected("recvmsg returned an invalid length");
    };
    if length == 0 {
        return ControlReceive::Closed;
    }
    let command = match &payload[..length] {
        b"status" => ControlCommand::Status,
        b"reload" => ControlCommand::Reload,
        _ => ControlCommand::Invalid,
    };
    ControlReceive::Command(command)
}

fn send_response(fd: RawFd, response: &[u8]) -> io::Result<()> {
    let mut iovec = Iovec {
        // sendmsg's iovec ABI uses a mutable pointer even though this call
        // only reads the response bytes.
        iov_base: response.as_ptr().cast_mut().cast(),
        iov_len: response.len(),
    };
    let message = MsgHdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: (&mut iovec as *mut Iovec),
        msg_iovlen: 1,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    let mut interrupted = false;
    let sent = loop {
        // MSG_NOSIGNAL is per-send and cannot alter the daemon's signal
        // disposition for unrelated code.  It guarantees a disconnected
        // status client produces EPIPE/ECONNRESET rather than SIGPIPE death.
        // SAFETY: the message points to the live response/iovec buffers and
        // the fd is an accepted socket owned by this listener.
        let sent = unsafe { sendmsg(fd, &message, MSG_NOSIGNAL) };
        if sent >= 0 {
            break sent;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(EINTR) && !interrupted {
            interrupted = true;
            continue;
        }
        return Err(error);
    };

    if usize::try_from(sent).ok() != Some(response.len()) {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "SOCK_SEQPACKET sendmsg returned a short response",
        ));
    }
    Ok(())
}

fn receive_response(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut payload = [0_u8; MAX_RESPONSE_BYTES];
    let mut control = [0_u8; CONTROL_CMSG_BUFFER_BYTES];
    let mut iovec = Iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message = MsgHdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iovec,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };

    let length = loop {
        // SAFETY: the response buffers and MsgHdr are live for this blocking
        // client call; MSG_CMSG_CLOEXEC protects any unexpected passed fd.
        let length = unsafe { recvmsg(fd, &mut message, MSG_CMSG_CLOEXEC) };
        if length >= 0 {
            break length;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(EINTR) {
            continue;
        }
        return Err(error);
    };

    let control_length = message.msg_controllen.min(control.len());
    close_received_fds(&control[..control_length]);
    if message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control response was truncated",
        ));
    }
    let length = usize::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control response length",
        )
    })?;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control daemon closed the connection without a response",
        ));
    }
    Ok(payload[..length].to_vec())
}

fn request_path(path: &Path, request: &[u8]) -> Result<Vec<u8>, String> {
    let address = ControlAddress::from_path(path)?;
    if request.len() > MAX_REQUEST_BYTES {
        return Err(format!(
            "control request is too long: {} bytes (maximum {})",
            request.len(),
            MAX_REQUEST_BYTES
        ));
    }
    // SAFETY: `socket(2)` receives only scalar ABI arguments; the returned
    // AF_UNIX SOCK_SEQPACKET descriptor is owned by this request operation.
    let fd = unsafe { socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "cannot create control client socket: {}",
            io::Error::last_os_error()
        ));
    }

    let result = (|| {
        let connected = loop {
            // SAFETY: address is initialized and fd is owned by this client.
            let connected = unsafe { connect(fd, &address.sockaddr, address.length) };
            if connected == 0 {
                break Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(EINTR) {
                continue;
            }
            break Err(error);
        };
        connected.map_err(|error| format!("cannot connect to control socket {path:?}: {error}"))?;

        send_client_request(fd, request)
            .map_err(|error| format!("cannot send control request to {path:?}: {error}"))?;
        receive_response(fd)
            .map_err(|error| format!("cannot receive control response from {path:?}: {error}"))
    })();
    // SAFETY: fd was created by this function and remains owned until here.
    let _ = unsafe { close(fd) };
    result
}

fn send_client_request(fd: RawFd, request: &[u8]) -> io::Result<()> {
    let mut iovec = Iovec {
        iov_base: request.as_ptr().cast_mut().cast(),
        iov_len: request.len(),
    };
    let message = MsgHdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iovec,
        msg_iovlen: 1,
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let mut interrupted = false;
    let sent = loop {
        // SAFETY: request and iovec remain live for this sendmsg call; the
        // client fd is owned by the caller.
        let sent = unsafe { sendmsg(fd, &message, MSG_NOSIGNAL) };
        if sent >= 0 {
            break sent;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(EINTR) && !interrupted {
            interrupted = true;
            continue;
        }
        return Err(error);
    };
    if usize::try_from(sent).ok() != Some(request.len()) {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "SOCK_SEQPACKET sendmsg returned a short request",
        ));
    }
    Ok(())
}

pub(crate) fn request_status() -> Result<(), String> {
    let path = control_socket_path()?;
    let response = request_path(&path, b"status")?;
    let response = String::from_utf8(response)
        .map_err(|error| format!("control status response was not UTF-8: {error}"))?;
    if response.contains('\n') || response.contains('\r') {
        return Err("control status response was not a single observability line".to_owned());
    }
    println!("{response}");
    Ok(())
}

fn is_peer_disconnect(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(EPIPE | ECONNRESET))
}

fn close_received_fds(control: &[u8]) {
    let header_len = std::mem::size_of::<CmsgHdr>();
    let mut offset = 0;
    while offset <= control.len() {
        let Some(header_end) = offset.checked_add(header_len) else {
            break;
        };
        if header_end > control.len() {
            break;
        }
        // SAFETY: the bounds check above covers a possibly unaligned CmsgHdr;
        // read_unaligned is used because the ancillary byte buffer is only
        // byte-aligned by contract.
        let header = unsafe { ptr::read_unaligned(control.as_ptr().add(offset).cast::<CmsgHdr>()) };
        if header.cmsg_len < header_len {
            break;
        }
        let Some(declared_end) = offset.checked_add(header.cmsg_len) else {
            break;
        };
        // If the kernel truncated this cmsg, close every complete fd in the
        // bytes that did arrive.  MSG_CTRUNC is still rejected by the caller.
        let available_end = declared_end.min(control.len());
        if header.cmsg_level == SOL_SOCKET && header.cmsg_type == SCM_RIGHTS {
            let data = &control[header_end..available_end];
            for bytes in data.chunks_exact(std::mem::size_of::<std::ffi::c_int>()) {
                // SAFETY: chunks_exact gives a complete c_int-sized value;
                // read_unaligned handles ancillary alignment.
                let received_fd =
                    unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<std::ffi::c_int>()) };
                if received_fd >= 0 {
                    // SAFETY: SCM_RIGHTS created this descriptor in this
                    // process; closing it is the deliberate ownership action.
                    let _ = unsafe { close(received_fd) };
                }
            }
        }
        if declared_end > control.len() {
            break;
        }
        let Some(aligned_len) = cmsg_align(header.cmsg_len) else {
            break;
        };
        if aligned_len == 0 {
            break;
        }
        let Some(next_offset) = offset.checked_add(aligned_len) else {
            break;
        };
        if next_offset <= offset {
            break;
        }
        offset = next_offset;
    }
}

fn cmsg_align(length: usize) -> Option<usize> {
    let alignment = std::mem::size_of::<usize>();
    length
        .checked_add(alignment - 1)
        .map(|aligned| aligned & !(alignment - 1))
}

// `sd_notify.rs` declares the same libc bind symbol for its own identically
// laid-out sockaddr_un type.  The module-local declarations remain ABI
// compatible, but rustc's cross-module lint cannot prove that from the
// private Rust types.
#[allow(clashing_extern_declarations)]
unsafe extern "C" {
    fn socket(
        domain: std::ffi::c_int,
        socket_type: std::ffi::c_int,
        protocol: std::ffi::c_int,
    ) -> std::ffi::c_int;
    #[link_name = "bind"]
    fn control_bind(
        socket: std::ffi::c_int,
        address: *const SockAddrUn,
        address_length: u32,
    ) -> std::ffi::c_int;
    fn connect(
        socket: std::ffi::c_int,
        address: *const SockAddrUn,
        address_length: u32,
    ) -> std::ffi::c_int;
    fn listen(socket: std::ffi::c_int, backlog: std::ffi::c_int) -> std::ffi::c_int;
    fn accept4(
        socket: std::ffi::c_int,
        address: *mut std::ffi::c_void,
        address_length: *mut u32,
        flags: std::ffi::c_int,
    ) -> std::ffi::c_int;
    // SAFETY: this declaration matches Linux libc's openat(2) ABI; callers
    // must provide a valid pathname for the duration of the call and own any
    // nonnegative descriptor returned by it.
    fn openat(
        directory_fd: std::ffi::c_int,
        path: *const std::ffi::c_char,
        flags: std::ffi::c_int,
        mode: std::ffi::c_uint,
    ) -> std::ffi::c_int;
    // SAFETY: this declaration matches Linux libc's unlinkat(2) ABI; callers
    // must provide a valid pathname for the duration of the call and keep the
    // directory descriptor valid until the call returns.
    fn unlinkat(
        directory_fd: std::ffi::c_int,
        path: *const std::ffi::c_char,
        flags: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn getsockopt(
        socket: std::ffi::c_int,
        level: std::ffi::c_int,
        option: std::ffi::c_int,
        value: *mut std::ffi::c_void,
        value_length: *mut u32,
    ) -> std::ffi::c_int;
    fn poll(
        file_descriptors: *mut PollFd,
        count: usize,
        timeout_milliseconds: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn renameat2(
        old_directory: std::ffi::c_int,
        old_path: *const std::ffi::c_char,
        new_directory: std::ffi::c_int,
        new_path: *const std::ffi::c_char,
        flags: std::ffi::c_uint,
    ) -> std::ffi::c_int;
    fn sendmsg(socket: std::ffi::c_int, message: *const MsgHdr, flags: std::ffi::c_int) -> isize;
    fn recvmsg(socket: std::ffi::c_int, message: *mut MsgHdr, flags: std::ffi::c_int) -> isize;
    fn geteuid() -> u32;
    fn getegid() -> u32;
    fn close(fd: std::ffi::c_int) -> std::ffi::c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        os::{
            fd::AsRawFd,
            unix::{
                ffi::OsStringExt,
                fs::{symlink, MetadataExt},
            },
        },
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    const SHUT_RDWR: std::ffi::c_int = 2;
    static NEXT_TEST_SOCKET: AtomicU64 = AtomicU64::new(0);

    fn is_sandbox_ancestor_ownership_error(error: &str) -> bool {
        error.contains("control socket ancestor directory")
            && error.contains(" is owned by uid ")
            && error.contains("; refusing to bind")
    }

    fn unique_path() -> PathBuf {
        let root = std::env::temp_dir().join(format!("ruster-control-tests-{}", process::id()));
        fs::create_dir_all(&root).expect("control socket test directory must exist");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("control socket test directory must be private");
        let id = NEXT_TEST_SOCKET.fetch_add(1, Ordering::Relaxed);
        root.join(format!("ruster-control-{id}.sock"))
    }

    fn listener_or_skip(path: &Path) -> Option<ControlListener> {
        match ControlListener::bind_path(path) {
            Ok(listener) => Some(listener),
            Err(error)
                if error.contains("Operation not permitted")
                    || error.contains("Permission denied")
                    || is_sandbox_ancestor_ownership_error(&error) =>
            {
                println!(
                    "control socket test skipped: SOCK_SEQPACKET bind is unavailable: {error}"
                );
                None
            }
            Err(error) => panic!("control listener must bind: {error}"),
        }
    }

    fn client(path: &Path) -> RawFd {
        client_with_socket_type(path, SOCK_SEQPACKET)
    }

    fn client_with_socket_type(path: &Path, socket_type: std::ffi::c_int) -> RawFd {
        let address = ControlAddress::from_path(path).expect("test path must fit sun_path");
        // SAFETY: this test creates a Linux AF_UNIX client of the requested
        // local socket type.
        let fd = unsafe { socket(AF_UNIX, socket_type | SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "test client socket must be created");
        // SAFETY: address is initialized and fd is owned by this test.
        let result = unsafe { connect(fd, &address.sockaddr, address.length) };
        assert_eq!(
            result,
            0,
            "test client must connect: {:?}",
            io::Error::last_os_error()
        );
        fd
    }

    fn stream_listener_or_skip(path: &Path) -> Option<ControlListener> {
        let address = ControlAddress::from_path(path).expect("test path must fit sun_path");
        // SAFETY: this test creates a Linux AF_UNIX stream listener so the
        // accept budget can be exercised where seqpacket is unavailable.
        let fd = unsafe { socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "test stream listener socket must be created");
        // SAFETY: address is initialized and fd is owned by this test.
        if unsafe { control_bind(fd, &address.sockaddr, address.length) } < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: fd is owned by this test.
            let _ = unsafe { close(fd) };
            if matches!(error.raw_os_error(), Some(1 | 13)) {
                println!("control socket test skipped: stream bind is unavailable: {error}");
                return None;
            }
            panic!("test stream listener must bind: {error}");
        }
        // SAFETY: fd is the bound AF_UNIX stream listener and the backlog is finite.
        let listen_result = unsafe { listen(fd, MAX_PENDING_CLIENTS as std::ffi::c_int) };
        assert_eq!(
            listen_result,
            0,
            "test stream listener must listen: {:?}",
            io::Error::last_os_error()
        );
        let identity = socket_identity(path).expect("test stream listener identity must exist");
        let parent = path
            .parent()
            .expect("test stream listener path must have a parent");
        let parent_fd = open_directory_fd(parent).expect("test stream listener parent must open");
        let file_name = path
            .file_name()
            .expect("test stream listener path must have a file name")
            .as_bytes()
            .to_vec();
        Some(ControlListener {
            fd,
            path: path.to_owned(),
            file_name,
            parent_fd,
            identity,
            // SAFETY: `geteuid(2)` has no pointer arguments and returns the
            // current test process's effective uid as a scalar value.
            daemon_uid: unsafe { geteuid() },
            // SAFETY: `getegid(2)` has no pointer arguments and returns the
            // current test process's effective gid as a scalar value.
            daemon_gid: unsafe { getegid() },
            clients: Vec::with_capacity(MAX_PENDING_CLIENTS),
        })
    }

    fn nonblocking_client_connect(path: &Path) -> RawFd {
        let address = ControlAddress::from_path(path).expect("test path must fit sun_path");
        // SAFETY: this test creates a Linux AF_UNIX stream client whose
        // nonblocking connect cannot wait while the test fills the queue.
        let fd = unsafe { socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "test stream client socket must be created");
        // SAFETY: address is initialized and fd is owned by this test.
        let result = unsafe { connect(fd, &address.sockaddr, address.length) };
        if result < 0 {
            let error = io::Error::last_os_error();
            assert!(
                matches!(error.raw_os_error(), Some(EINPROGRESS | EAGAIN)),
                "nonblocking test client connect must queue or report progress: {error}"
            );
        }
        fd
    }

    fn completed_nonblocking_client_connect(path: &Path, peer_kind: &str) -> RawFd {
        let address = ControlAddress::from_path(path).expect("test path must fit sun_path");
        // SAFETY: this test creates a Linux AF_UNIX stream client whose
        // nonblocking connect is completed below without an unbounded wait.
        let fd = unsafe { socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        assert!(
            fd >= 0,
            "{peer_kind} control peer connect socket creation failed before deadline {:?}: {}",
            CONTROL_CLIENT_TIMEOUT,
            io::Error::last_os_error()
        );
        let deadline = Instant::now()
            .checked_add(CONTROL_CLIENT_TIMEOUT)
            .unwrap_or_else(Instant::now);

        // SAFETY: address is initialized and fd is owned by this test.
        let result = unsafe { connect(fd, &address.sockaddr, address.length) };
        if result == 0 {
            assert!(
                Instant::now() <= deadline,
                "{peer_kind} control peer connect completed after deadline {:?}",
                CONTROL_CLIENT_TIMEOUT
            );
            return fd;
        }
        let error = io::Error::last_os_error();
        assert!(
            matches!(error.raw_os_error(), Some(EINPROGRESS | EAGAIN)),
            "{peer_kind} control peer connect must return 0, EINPROGRESS, or EAGAIN before deadline {:?}: {error}",
            CONTROL_CLIENT_TIMEOUT
        );

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "{peer_kind} control peer connect deadline {:?} exceeded while waiting",
                CONTROL_CLIENT_TIMEOUT
            );
            let mut poll_fd = PollFd {
                fd,
                events: POLLOUT,
                revents: 0,
            };
            let timeout_ms = poll_timeout_millis(remaining);
            // SAFETY: poll_fd points to one initialized pollfd for this call
            // and the timeout is finite; poll never retains the pointer.
            let polled = unsafe { poll(&mut poll_fd, 1, timeout_ms) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(EINTR) {
                    continue;
                }
                panic!(
                    "{peer_kind} control peer connect poll failed before deadline {:?}: {error}",
                    CONTROL_CLIENT_TIMEOUT
                );
            }
            assert_ne!(
                polled, 0,
                "{peer_kind} control peer connect deadline {:?} exceeded in poll",
                CONTROL_CLIENT_TIMEOUT
            );
            assert_eq!(
                poll_fd.revents & POLLNVAL,
                0,
                "{peer_kind} control peer connect poll reported invalid fd before deadline {:?}",
                CONTROL_CLIENT_TIMEOUT
            );
            if poll_fd.revents & (POLLOUT | POLLERR | POLLHUP) == 0 {
                continue;
            }

            let mut socket_error: std::ffi::c_int = 0;
            let mut length =
                u32::try_from(std::mem::size_of_val(&socket_error)).expect("SO_ERROR size fits");
            // SAFETY: socket_error and length are writable buffers of the
            // exact SO_ERROR ABI shape, and fd remains owned by this test.
            let result = unsafe {
                getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    (&mut socket_error as *mut std::ffi::c_int).cast(),
                    &mut length,
                )
            };
            assert_eq!(
                result,
                0,
                "{peer_kind} control peer connect SO_ERROR failed before deadline {:?}: {}",
                CONTROL_CLIENT_TIMEOUT,
                io::Error::last_os_error()
            );
            assert!(
                usize::try_from(length).unwrap_or(0) >= std::mem::size_of_val(&socket_error),
                "{peer_kind} control peer connect SO_ERROR returned a short value before deadline {:?}: length={length}",
                CONTROL_CLIENT_TIMEOUT
            );
            assert!(
                Instant::now() <= deadline,
                "{peer_kind} control peer connect completed after deadline {:?}",
                CONTROL_CLIENT_TIMEOUT
            );
            assert_eq!(
                socket_error,
                0,
                "{peer_kind} control peer connect SO_ERROR reported failure before deadline {:?}: {}",
                CONTROL_CLIENT_TIMEOUT,
                io::Error::from_raw_os_error(socket_error)
            );
            return fd;
        }
    }

    fn send_test_packet(fd: RawFd, payload: &[u8], control: &[u8]) {
        let mut iovec = Iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let message = MsgHdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
            msg_control: if control.is_empty() {
                ptr::null_mut()
            } else {
                control.as_ptr().cast_mut().cast()
            },
            msg_controllen: control.len(),
            msg_flags: 0,
        };
        // SAFETY: payload/control are live for this sendmsg call and fd is a
        // test-owned connected seqpacket socket.
        let sent = unsafe { sendmsg(fd, &message, MSG_NOSIGNAL) };
        assert_eq!(
            usize::try_from(sent).ok(),
            Some(payload.len()),
            "test request sendmsg must succeed: {:?}",
            io::Error::last_os_error()
        );
    }

    fn build_rights_control(fds: &[RawFd]) -> Vec<u8> {
        let data_len = fds
            .len()
            .checked_mul(std::mem::size_of::<std::ffi::c_int>())
            .expect("test cmsg length must fit");
        let cmsg_len = std::mem::size_of::<CmsgHdr>() + data_len;
        let control_len = cmsg_align(cmsg_len).expect("test cmsg length must align");
        let mut control = vec![0_u8; control_len];
        let header = CmsgHdr {
            cmsg_len,
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS,
        };
        // SAFETY: the aligned byte buffer is large enough for this header.
        unsafe {
            ptr::write_unaligned(control.as_mut_ptr().cast::<CmsgHdr>(), header);
        }
        for (index, fd) in fds.iter().copied().enumerate() {
            let offset =
                std::mem::size_of::<CmsgHdr>() + index * std::mem::size_of::<std::ffi::c_int>();
            // SAFETY: each offset is inside the cmsg data area and the value
            // is copied as the Linux SCM_RIGHTS integer representation.
            unsafe {
                ptr::write_unaligned(
                    control.as_mut_ptr().add(offset).cast::<std::ffi::c_int>(),
                    fd,
                );
            }
        }
        control
    }

    fn expect_no_response(fd: RawFd) {
        let error = receive_response(fd).expect_err("rejected request must not receive data");
        assert!(
            error.kind() == io::ErrorKind::UnexpectedEof
                || error.raw_os_error() == Some(ECONNRESET),
            "rejected request should close the connection: {error}"
        );
    }

    #[test]
    fn path_too_long_fails_before_bind_without_truncation() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(vec![b'x'; SUN_PATH_LEN]));
        let error = match ControlListener::bind_path(&path) {
            Ok(_) => panic!("long path must fail"),
            Err(error) => error,
        };
        assert!(error.contains("too long"), "error={error:?}");
        assert!(error.contains("maximum is 107"), "error={error:?}");
    }

    #[test]
    fn stale_socket_is_removed_only_after_refused_probe() {
        let path = unique_path();
        let address = ControlAddress::from_path(&path).expect("test path must fit sun_path");
        // SAFETY: this test creates a Linux AF_UNIX socket for a stale path.
        let fd = unsafe { socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "stale test socket must be created");
        // SAFETY: address is initialized and fd is owned by this test.
        let bind_result = unsafe { control_bind(fd, &address.sockaddr, address.length) };
        if bind_result < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: fd is owned by this test.
            let _ = unsafe { close(fd) };
            if matches!(error.raw_os_error(), Some(1 | 13)) {
                println!(
                    "control socket test skipped: SOCK_SEQPACKET bind is unavailable: {error}"
                );
                return;
            }
            panic!("stale test socket must bind: {error}");
        }
        // SAFETY: the bound fd is owned by this test; closing it leaves the
        // pathname behind without an accepting endpoint.
        let _ = unsafe { close(fd) };

        let Some(listener) = listener_or_skip(&path) else {
            return;
        };
        assert!(path.exists(), "new listener must own a pathname socket");
        drop(listener);
        assert!(!path.exists(), "listener drop must unlink its own socket");
    }

    #[test]
    fn authorization_predicate_matches_uid_gid_policy() {
        assert!(peer_is_authorized(0, 9999, 1000, 1001));
        assert!(peer_is_authorized(1000, 9999, 1000, 1001));
        assert!(peer_is_authorized(9999, 1001, 1000, 1001));
        assert!(!peer_is_authorized(9999, 9998, 1000, 1001));
    }

    #[test]
    fn rejected_backlog_peers_do_not_delay_authorized_peer() {
        const {
            assert!(
                MAX_ACCEPTS_PER_TICK > MAX_PENDING_CLIENTS,
                "the accept budget must cover the configured backlog plus the peer at its tail"
            );
        }
        let path = unique_path();
        let Some(mut listener) = stream_listener_or_skip(&path) else {
            return;
        };

        // Use the real SO_PEERCRED path, but make the first burst unauthorized
        // without requiring this unprivileged test process to impersonate a
        // second uid.  Restore the actual daemon identity before the peer at
        // the tail connects.  Complete all MAX_PENDING_CLIENTS - 1 (63)
        // rejected connects before adding the authorized tail, so the
        // listener's accept queue contains the whole 64-peer burst.  The
        // MAX_ACCEPTS_PER_TICK budget covers that exact queue in one tick.
        listener.daemon_uid = u32::MAX;
        listener.daemon_gid = u32::MAX;
        let rejected: Vec<_> = (0..MAX_PENDING_CLIENTS - 1)
            .map(|_| completed_nonblocking_client_connect(&path, "rejected"))
            .collect();
        // SAFETY: `geteuid(2)` has no pointer arguments and returns the
        // current test process's effective uid as a scalar value.
        listener.daemon_uid = unsafe { geteuid() };
        // SAFETY: `getegid(2)` has no pointer arguments and returns the
        // current test process's effective gid as a scalar value.
        listener.daemon_gid = unsafe { getegid() };

        let authorized = completed_nonblocking_client_connect(&path, "authorized");
        send_test_packet(authorized, b"status", &[]);
        let result = listener.process(|| "record_type=observability".to_owned());
        assert_eq!(
            result.requests_seen, 1,
            "the authorized peer behind rejected backlog peers must be serviced in one bounded tick"
        );
        assert_eq!(
            receive_response(authorized).expect("authorized peer must receive a response"),
            b"record_type=observability"
        );

        // SAFETY: every descriptor below is owned by this test client set.
        let _ = unsafe { close(authorized) };
        for fd in rejected {
            // SAFETY: every descriptor below is owned by this test client set.
            let _ = unsafe { close(fd) };
        }
        drop(listener);
    }

    #[test]
    fn full_stream_backlog_probe_is_bounded_and_conservative() {
        assert_ne!(
            CONTROL_PROBE_SOCKET_FLAGS & SOCK_NONBLOCK,
            0,
            "probe sockets must be nonblocking before connect"
        );
        let path = unique_path();
        let address = ControlAddress::from_path(&path).expect("test path must fit sun_path");
        // SAFETY: this test creates a Linux AF_UNIX stream listener.
        let server = unsafe { socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) };
        assert!(server >= 0, "probe server socket must be created");
        // SAFETY: address is initialized and server is owned by this test.
        let bind_result = unsafe { control_bind(server, &address.sockaddr, address.length) };
        if bind_result < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: server is owned by this test.
            let _ = unsafe { close(server) };
            if matches!(error.raw_os_error(), Some(1 | 13)) {
                println!("control socket test skipped: stream bind is unavailable: {error}");
                return;
            }
            panic!("probe server socket must bind: {error}");
        }
        // SAFETY: server is the bound stream socket and the backlog is finite.
        let listen_result = unsafe { listen(server, 1) };
        assert_eq!(
            listen_result,
            0,
            "probe server listen must succeed: {:?}",
            io::Error::last_os_error()
        );

        let clients: Vec<_> = (0..(MAX_PENDING_CLIENTS + 1))
            .map(|_| nonblocking_client_connect(&path))
            .collect();
        let started = Instant::now();
        let result = connect_probe(address, SOCK_STREAM);
        assert!(
            started.elapsed() <= Duration::from_millis(250) + Duration::from_millis(100),
            "probe exceeded its bounded deadline: {:?}",
            started.elapsed()
        );
        let error =
            result.expect_err("a full live stream queue must not look like a successful probe");
        assert_ne!(
            error.raw_os_error(),
            Some(ECONNREFUSED),
            "a full live stream queue must be treated conservatively, not as stale"
        );

        for fd in clients {
            // SAFETY: every descriptor below is owned by this test client set.
            let _ = unsafe { close(fd) };
        }
        // SAFETY: server is owned by this test.
        let _ = unsafe { close(server) };
        let _ = fs::remove_file(path);
    }

    #[test]
    fn writable_control_socket_parent_fails_closed_before_bind() {
        let parent = loop {
            let candidate = std::env::temp_dir().join(format!(
                "ruster-control-writable-parent-{}-{}",
                process::id(),
                NEXT_TEST_SOCKET.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("writable parent must be created: {error}"),
            }
        };
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777))
            .expect("writable parent mode must be set");
        let path = parent.join("control.sock");
        let victim = parent.join("victim");
        File::create(&victim).expect("victim must be created");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600))
            .expect("victim mode must be set");

        let error = match ControlListener::bind_path(&path) {
            Ok(listener) => {
                drop(listener);
                panic!("an attacker-writable control socket parent must fail closed")
            }
            Err(error) => error,
        };
        assert!(error.contains("parent directory"), "error={error:?}");
        assert_eq!(
            fs::metadata(&victim)
                .expect("victim metadata must be readable")
                .mode()
                & 0o777,
            0o600,
            "fail-closed setup must not change the victim mode"
        );
        assert!(
            !path.exists(),
            "fail-closed setup must not create the socket path"
        );
        fs::remove_file(&victim).expect("writable parent victim must be removed");
        fs::remove_dir(&parent).expect("writable parent must be removed");
    }

    #[test]
    fn writable_control_socket_ancestor_fails_closed_before_bind() {
        let root = std::env::temp_dir().join(format!(
            "ruster-control-writable-ancestor-{}-{}",
            process::id(),
            NEXT_TEST_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("private");
        fs::create_dir_all(&parent).expect("ancestor test directories must be created");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("writable ancestor mode must be set");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("private parent mode must be set");
        let path = parent.join("control.sock");

        let accepted = match ControlListener::bind_path(&path) {
            Ok(listener) => {
                drop(listener);
                false
            }
            Err(error) => {
                assert!(error.contains("group/other-writable"), "error={error:?}");
                true
            }
        };
        let _ = fs::remove_dir_all(&root);
        assert!(
            accepted,
            "an attacker-writable ancestor must fail closed before bind"
        );
    }

    #[test]
    fn symlink_replacement_during_publication_cannot_change_victim_mode() {
        let path = unique_path();
        let parent = path.parent().expect("test socket path must have a parent");
        let temporary_path = parent.join(format!(
            ".ruster-publication-test-{}",
            NEXT_TEST_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let victim = parent.join(format!(
            "ruster-victim-{}",
            NEXT_TEST_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        File::create(&temporary_path).expect("publication temporary path must be created");
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o660))
            .expect("publication temporary mode must be set");
        File::create(&victim).expect("victim must be created");
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600))
            .expect("victim mode must be set");
        symlink(&victim, &path).expect("attacker replacement symlink must be created");

        let error = publish_socket_path(&temporary_path, &path)
            .expect_err("RENAME_NOREPLACE must reject an inserted symlink");
        assert_eq!(error.raw_os_error(), Some(EEXIST), "error={error}");
        assert_eq!(
            fs::metadata(&victim)
                .expect("victim metadata must be readable")
                .mode()
                & 0o777,
            0o600,
            "publication must never follow the replacement symlink to chmod its victim"
        );
        assert!(
            path.is_symlink(),
            "the replacement symlink must remain untouched"
        );
        assert!(
            temporary_path.exists(),
            "failed publication must leave the caller-owned temporary inode for cleanup"
        );

        fs::remove_file(&temporary_path).expect("temporary publication path must be removed");
        fs::remove_file(&path).expect("replacement symlink must be removed");
        fs::remove_file(&victim).expect("victim must be removed");
    }

    #[test]
    fn status_response_is_a_single_observability_line() {
        let path = unique_path();
        let Some(mut listener) = listener_or_skip(&path) else {
            return;
        };
        let fd = client(&path);
        send_test_packet(fd, b"status", &[]);
        let result =
            listener.process(|| "record_type=observability config_generation=1".to_owned());
        assert_eq!(result.requests_seen, 1);
        assert!(!result.reload_requested);
        let mode = fs::metadata(&path)
            .expect("control socket metadata must be readable")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660, "control socket mode must not depend on umask");
        let response = receive_response(fd).expect("status response must be received");
        assert_eq!(
            response, b"record_type=observability config_generation=1",
            "status must preserve the supplied observability line"
        );
        // SAFETY: fd is owned by this test client.
        let _ = unsafe { close(fd) };
        drop(listener);
        assert!(!path.exists());
    }

    #[test]
    fn msg_trunc_request_is_rejected_without_partial_processing() {
        let path = unique_path();
        let Some(mut listener) = listener_or_skip(&path) else {
            return;
        };
        let fd = client(&path);
        send_test_packet(fd, &[b'x'; MAX_REQUEST_BYTES + 1], &[]);
        let result = listener.process(|| "record_type=observability should-not-be-sent".to_owned());
        assert_eq!(result.requests_seen, 1);
        expect_no_response(fd);
        // SAFETY: fd is owned by this test client.
        let _ = unsafe { close(fd) };
        drop(listener);
    }

    #[test]
    fn msg_ctrunc_request_is_rejected_and_received_fds_are_closed() {
        let path = unique_path();
        let Some(mut listener) = listener_or_skip(&path) else {
            return;
        };
        let fd = client(&path);
        let source = File::open("/dev/null").expect("test must open a source fd");
        let rights = build_rights_control(&vec![source.as_raw_fd(); 64]);
        assert!(
            rights.len() > CONTROL_CMSG_BUFFER_BYTES,
            "test ancillary data must exceed the receiver buffer"
        );
        send_test_packet(fd, b"status", &rights);
        let result = listener.process(|| "record_type=observability should-not-be-sent".to_owned());
        assert_eq!(result.requests_seen, 1);
        expect_no_response(fd);
        // SAFETY: fd is owned by this test client.
        let _ = unsafe { close(fd) };
        drop(listener);
    }

    #[test]
    fn closed_client_cannot_kill_process_during_response() {
        let path = unique_path();
        let Some(mut listener) = listener_or_skip(&path) else {
            return;
        };
        let fd = client(&path);
        send_test_packet(fd, b"status", &[]);
        // Put the accepted fd into the listener queue first, then close the
        // peer.  The queued request remains available while sendmsg observes
        // the peer shutdown and exercises MSG_NOSIGNAL.
        listener.accept_connections();
        // SAFETY: fd is a connected test socket owned by this test.
        let shutdown_result = unsafe { shutdown(fd, SHUT_RDWR) };
        assert_eq!(shutdown_result, 0, "test client shutdown must succeed");
        // SAFETY: fd is owned by this test client.
        let _ = unsafe { close(fd) };
        let result = listener.process(|| "record_type=observability".to_owned());
        assert_eq!(result.requests_seen, 1);
        drop(listener);
    }

    unsafe extern "C" {
        fn shutdown(socket: std::ffi::c_int, how: std::ffi::c_int) -> std::ffi::c_int;
    }
}

//! Attaching to the persistent TUN devices confd creates, one per VRF, and to the
//! TAP devices of the interfaces that run IS-IS or OSPF, through a minimal private
//! FFI (`ioctl(TUNSETIFF)`).
//!
//! The device of VRF `name` is `rt-<name>`. It carries bare IP packets (`IFF_TUN`
//! with `IFF_NO_PI`). The device of interface `name` is `rp-<name>`; it carries
//! Ethernet frames (`IFF_TAP` with `IFF_NO_PI`). The FE only attaches to a
//! persistent device (one confd made): when TUNSETIFF made a new one instead, the FE
//! closes it again, which removes it. So the kernel's addresses and routes on the
//! device outlive an FE restart. A TAP device's carrier is up only while the FE
//! has it open; the FE also sets it (`ioctl(TUNSETCARRIER)`) to the link state of
//! the interface it stands for, so IS-IS and OSPF see a port go down at once
//! instead of after their hold time.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;

/// The longest Linux interface name (IFNAMSIZ - 1).
const NAME_MAX: usize = 15;

/// The TUN device of VRF `vrf`, or `None` when the name would be too long.
pub fn device(vrf: &str) -> Option<String> {
    let name = format!("rt-{vrf}");
    (name.len() <= NAME_MAX && name.bytes().all(|b| b.is_ascii_graphic() && b != b'/'))
        .then_some(name)
}

/// The TAP device of interface `interface`, or `None` when the name would be too
/// long.
pub fn tap_device(interface: &str) -> Option<String> {
    let name = format!("rp-{interface}");
    (name.len() <= NAME_MAX && name.bytes().all(|b| b.is_ascii_graphic() && b != b'/'))
        .then_some(name)
}

/// The device's interface index in this network namespace, or `None` when there is
/// no such device. A device made again gets another index.
pub fn index(device: &str) -> Option<u32> {
    let path = std::path::Path::new("/sys/class/net")
        .join(device)
        .join("ifindex");
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Whether `device`'s link is up: its carrier is on. A device that is down or not
/// there has none.
pub fn carrier(device: &str) -> bool {
    let path = std::path::Path::new("/sys/class/net")
        .join(device)
        .join("carrier");
    std::fs::read_to_string(path).is_ok_and(|text| text.trim() == "1")
}

/// Sets the carrier of the TUN or TAP device `file` is attached to.
pub fn set_carrier(file: &File, up: bool) -> io::Result<()> {
    imp::set_carrier(file, up)
}

/// Opens `/dev/net/tun`, non-blocking, attached to the existing `device`: a TAP
/// device with `tap`, else a TUN device.
pub fn open(device: &str, tap: bool) -> io::Result<File> {
    const O_NONBLOCK: i32 = 0o4000;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_NONBLOCK)
        .open("/dev/net/tun")?;
    imp::attach(&file, device, tap)?;
    Ok(file)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_short, c_ulong};

    /// `_IOW('T', 202, int)`, the same on every Linux architecture ruster builds for
    /// (x86_64 and aarch64).
    const TUNSETIFF: c_ulong = 0x4004_54ca;
    /// `_IOR('T', 210, unsigned int)`.
    const TUNGETIFF: c_ulong = 0x8004_54d2;
    const IFF_TUN: c_short = 0x0001;
    const IFF_TAP: c_short = 0x0002;
    const IFF_NO_PI: c_short = 0x1000;
    const IFF_PERSIST: c_short = 0x0800;
    /// `_IOW('T', 226, int)`.
    const TUNSETCARRIER: c_ulong = 0x4004_54e2;

    /// `struct ifreq` as TUNSETIFF reads it: the name, then the flags at the start
    /// of the 24-byte union.
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: c_short,
        _pad: [u8; 22],
    }

    extern "C" {
        // `int ioctl(int, unsigned long, ...)` from the C library std links. TUNSETIFF
        // takes a pointer to `struct ifreq`.
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    pub fn attach(file: &File, device: &str, tap: bool) -> io::Result<()> {
        let mode = if tap { IFF_TAP } else { IFF_TUN };
        let mut request = IfReq {
            name: [0; 16],
            flags: mode | IFF_NO_PI,
            _pad: [0; 22],
        };
        let bytes = device.as_bytes();
        if bytes.is_empty() || bytes.len() >= request.name.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device name length",
            ));
        }
        request.name[..bytes.len()].copy_from_slice(bytes);
        // SAFETY: `ioctl` is the C library function with the declared variadic ABI.
        // The fd is an open `/dev/net/tun` owned by `file`, alive for the call.
        // TUNSETIFF reads and writes one `struct ifreq` (40 bytes on 64-bit Linux,
        // which `IfReq` is: 16 + 2 + 22) through the pointer, which is valid and
        // exclusively borrowed for the call; nothing keeps it afterwards.
        let status = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, std::ptr::addr_of_mut!(request)) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        // TUNSETIFF creates a device when none is there; only a persistent one,
        // made by confd, is attached to. The caller drops `file` otherwise, which
        // removes a device created here.
        let mut current = IfReq {
            name: [0; 16],
            flags: 0,
            _pad: [0; 22],
        };
        // SAFETY: as above; TUNGETIFF writes one `struct ifreq` through the pointer.
        let status = unsafe { ioctl(file.as_raw_fd(), TUNGETIFF, std::ptr::addr_of_mut!(current)) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        if current.flags & IFF_PERSIST == 0 || current.flags & (IFF_TUN | IFF_TAP) != mode {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "not a persistent TUN or TAP device made by confd",
            ));
        }
        Ok(())
    }

    pub fn set_carrier(file: &File, up: bool) -> io::Result<()> {
        let carrier: c_int = up.into();
        // SAFETY: `ioctl` as above. The fd is an open `/dev/net/tun` attached to a
        // device, owned by `file` and alive for the call. TUNSETCARRIER reads one
        // `int` through the pointer, which is valid for the call; nothing keeps it.
        let status = unsafe { ioctl(file.as_raw_fd(), TUNSETCARRIER, std::ptr::addr_of!(carrier)) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    const _: () = assert!(std::mem::size_of::<IfReq>() == 40);
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn attach(_file: &std::fs::File, _device: &str, _tap: bool) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN needs Linux",
        ))
    }

    pub fn set_carrier(_file: &std::fs::File, _up: bool) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN needs Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_fit_linux() {
        assert_eq!(device("default").as_deref(), Some("rt-default"));
        assert_eq!(device("red").as_deref(), Some("rt-red"));
        assert_eq!(device("a-very-long-vrf"), None);
        assert_eq!(device("a/b"), None);
        assert_eq!(tap_device("wan.100").as_deref(), Some("rp-wan.100"));
        assert_eq!(tap_device("thirteenchars"), None);
    }
}

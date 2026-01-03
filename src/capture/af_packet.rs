//! AF_PACKET socket implementation

use super::{Capture, RxInfo};
use crate::{Error, Result};
use std::ffi::CString;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;

/// AF_PACKET socket wrapper
pub struct AfPacketSocket {
    async_fd: AsyncFd<RawFd>,
    ifindex: i32,
}

impl AfPacketSocket {
    /// Create a new AF_PACKET socket bound to the specified interface
    pub fn bind(ifname: &str) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as i32,
            )
        };

        if fd < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        // Get interface index
        let ifindex = Self::get_ifindex(fd, ifname)?;

        // Bind to interface
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };

        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        // Set non-blocking
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };

        // Enable promiscuous mode
        Self::set_promisc(fd, ifindex, true)?;

        let async_fd = AsyncFd::new(fd).map_err(Error::Io)?;

        Ok(Self { async_fd, ifindex })
    }

    fn get_ifindex(fd: RawFd, ifname: &str) -> Result<i32> {
        let ifname_c = CString::new(ifname).map_err(|_| Error::InterfaceNotFound {
            name: ifname.to_string(),
        })?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = ifname_c.as_bytes_with_nul();
        ifr.ifr_name[..name_bytes.len()].copy_from_slice(unsafe {
            std::slice::from_raw_parts(name_bytes.as_ptr() as *const i8, name_bytes.len())
        });

        let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX, &mut ifr) };
        if ret < 0 {
            return Err(Error::InterfaceNotFound {
                name: ifname.to_string(),
            });
        }

        Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
    }

    fn set_promisc(fd: RawFd, ifindex: i32, enable: bool) -> Result<()> {
        let mreq = libc::packet_mreq {
            mr_ifindex: ifindex,
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };

        let optname = if enable {
            libc::PACKET_ADD_MEMBERSHIP
        } else {
            libc::PACKET_DROP_MEMBERSHIP
        };

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                optname,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as u32,
            )
        };

        if ret < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Receive a packet (async)
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<RxInfo> {
        loop {
            let mut guard = self.async_fd.readable_mut().await.map_err(Error::Io)?;

            match guard.try_io(|inner| {
                let fd = *inner.get_ref();
                let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(len)) => {
                    return Ok(RxInfo { len, vlan_id: None });
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Send a packet (async)
    pub async fn send(&mut self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.async_fd.writable_mut().await.map_err(Error::Io)?;

            match guard.try_io(|inner| {
                let fd = *inner.get_ref();
                let n = unsafe { libc::send(fd, buf.as_ptr() as *const _, buf.len(), 0) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(len)) => return Ok(len),
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_would_block) => continue,
            }
        }
    }

    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }
}

impl AsRawFd for AfPacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        *self.async_fd.get_ref()
    }
}

impl Drop for AfPacketSocket {
    fn drop(&mut self) {
        let _ = Self::set_promisc(*self.async_fd.get_ref(), self.ifindex, false);
        unsafe { libc::close(*self.async_fd.get_ref()) };
    }
}

impl Capture for AfPacketSocket {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<RxInfo> {
        AfPacketSocket::recv(self, buf).await
    }

    async fn send(&mut self, buf: &[u8]) -> Result<usize> {
        AfPacketSocket::send(self, buf).await
    }
}

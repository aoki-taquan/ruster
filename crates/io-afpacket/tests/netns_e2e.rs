#![cfg(target_os = "linux")]

use ruster_core::{DropReason, IfId, PacketBatch, PacketIo};
use ruster_io_afpacket::{
    AfPacketIo, AfPacketPlatform, PlatformError, PortConfig, RingGeometry, ValidatedConfig,
};
use std::{
    env::VarError,
    ffi::{c_char, c_int, c_void, CString},
    io,
    mem::size_of,
    os::fd::RawFd,
    thread,
    time::{Duration, Instant},
};

const AF_PACKET: c_int = 17;
const SOCK_RAW: c_int = 3;
const SOCK_CLOEXEC: c_int = 0x8_0000;
const SOL_PACKET: c_int = 263;
const PACKET_IGNORE_OUTGOING: c_int = 23;
const ETH_P_ALL: u16 = 0x0003;
const MSG_DONTWAIT: c_int = 0x40;
const POLLIN: i16 = 0x0001;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const PACKET_OUTGOING: u8 = 4;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EPERM: i32 = 1;
const EACCES: i32 = 13;
const SC_PAGESIZE: c_int = 30;

const DEFAULT_INTERFACE: &str = "eth0";
const MAX_FRAME_LEN: usize = 1_514;
const FRAME_LEN: usize = 60;
const RX_BUDGET: usize = 1;
const RX_BLOCK_RETIRE_TIMEOUT_MS: u32 = 20;
const E2E_TIMEOUT: Duration = Duration::from_secs(10);
const PEER_POLL_SLICE: Duration = Duration::from_millis(50);
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const SOURCE_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x73, 0x74, 0x14];

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

struct RawPacketSocket {
    fd: RawFd,
}

impl RawPacketSocket {
    fn fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawPacketSocket {
    fn drop(&mut self) {
        // SAFETY: this is the sole owner of the descriptor returned by socket.
        unsafe {
            close(self.fd);
        }
    }
}

#[test]
fn netns_e2e() {
    if !privileged_e2e_requested() {
        return;
    }

    match std::env::var("RUSTER_E2E_ROLE") {
        Ok(role) if role == "peer" => run_peer(),
        Ok(role) if role == "target" => run_target(),
        Ok(role) => panic!("privileged AF_PACKET E2E has unknown role {role:?}"),
        Err(VarError::NotPresent) => run_target(),
        Err(VarError::NotUnicode(_)) => {
            panic!("privileged AF_PACKET E2E role is not valid UTF-8")
        }
    }
}

fn privileged_e2e_requested() -> bool {
    match std::env::var("RUSTER_PRIVILEGED_E2E") {
        Ok(value) if value == "1" => true,
        Ok(value) => {
            println!(
                "netns_e2e: skipped: RUSTER_PRIVILEGED_E2E={value:?}; set it to 1 to request the privileged E2E"
            );
            false
        }
        Err(VarError::NotPresent) => {
            println!(
                "netns_e2e: skipped: RUSTER_PRIVILEGED_E2E is unset; set it to 1 to request the privileged E2E"
            );
            false
        }
        Err(VarError::NotUnicode(_)) => {
            println!(
                "netns_e2e: skipped: RUSTER_PRIVILEGED_E2E is not valid UTF-8; set it to 1 to request the privileged E2E"
            );
            false
        }
    }
}

fn run_target() {
    let interface_name = configured_interface();
    let if_index = interface_index(&interface_name);
    let page_size = system_page_size();

    if let Err(error) = AfPacketPlatform::ensure_supported() {
        panic!("privileged AF_PACKET E2E platform validation failed: {error}");
    }

    let interface = IfId(1);
    let rx = RingGeometry {
        block_size: 4_096,
        block_count: 2,
        frame_size: 2_048,
        frame_count: 4,
        retire_timeout_ms: RX_BLOCK_RETIRE_TIMEOUT_MS,
        private_size: 0,
        feature_flags: 0,
    };
    let tx = RingGeometry {
        retire_timeout_ms: 0,
        private_size: 0,
        feature_flags: 0,
        ..rx
    };
    let config = ValidatedConfig::new(
        &[PortConfig {
            interface,
            if_index,
            rx,
            tx,
        }],
        page_size,
        MAX_FRAME_LEN,
    )
    .unwrap_or_else(|error| panic!("privileged AF_PACKET E2E configuration failed: {error:?}"));

    let mut io = AfPacketIo::open(config).unwrap_or_else(|error| {
        panic_platform_error("AfPacketIo::open", error);
    });
    let expected = expected_frame();
    let deadline = Instant::now() + E2E_TIMEOUT;
    let mut received_and_transmitted = false;

    while !received_and_transmitted && Instant::now() < deadline {
        let mut batch = io
            .receive(RX_BUDGET)
            .unwrap_or_else(|error| panic!("privileged AF_PACKET E2E receive failed: {error:?}"));
        let mut slots = 0_usize;
        while let Some(mut lease) = batch.next_packet() {
            slots += 1;
            assert!(
                slots <= RX_BUDGET,
                "PacketIo::receive returned more than its budget: {slots} > {RX_BUDGET}"
            );
            if lease.bytes_mut() == expected.as_slice() && !received_and_transmitted {
                lease.commit(interface);
                received_and_transmitted = true;
            } else {
                lease.recycle(DropReason::RouteMiss);
            }
        }

        let completion = batch.finish();
        assert!(
            completion.invariants_hold(),
            "AF_PACKET batch completion invariants failed: {completion:?}"
        );
        assert!(
            completion.error.is_none(),
            "AF_PACKET batch completed with an error: {completion:?}"
        );
        if received_and_transmitted {
            assert_eq!(
                completion.tx_requested, 1,
                "the matching RX lease must request exactly one transmission"
            );
            assert_eq!(
                completion.tx_accepted, 1,
                "the matching RX lease transmission must be accepted"
            );
            assert_eq!(
                completion.tx_rejected, 0,
                "the matching RX lease transmission must not be rejected"
            );
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }

    assert!(
        received_and_transmitted,
        "timed out waiting for the peer frame on interface {interface_name:?}"
    );
}

fn run_peer() {
    let interface_name = configured_interface();
    let expected = expected_frame();
    let destination = packet_address(interface_index(&interface_name), Some(&BROADCAST_MAC));
    let sender = open_raw_socket(&interface_name, false).unwrap_or_else(|error| {
        panic_raw_socket_error("peer sender socket setup", error);
    });
    let observer = open_raw_socket(&interface_name, true).unwrap_or_else(|error| {
        panic_raw_socket_error("peer observer socket setup", error);
    });
    let deadline = Instant::now() + E2E_TIMEOUT;
    let mut receive_buffer = [0_u8; 2_048];

    println!("netns_e2e peer: sending the known frame on host-side interface {interface_name:?}");
    while Instant::now() < deadline {
        match send_frame(sender.fd(), &destination, &expected) {
            Ok(()) => {}
            Err(error) if is_would_block(&error) => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(error) => panic!("privileged AF_PACKET E2E peer send failed: {error}"),
        }

        let wait_deadline = (Instant::now() + PEER_POLL_SLICE).min(deadline);
        if !poll_readable(observer.fd(), wait_deadline)
            .unwrap_or_else(|error| panic!("privileged AF_PACKET E2E peer poll failed: {error}"))
        {
            continue;
        }

        while let Some((length, packet_type)) = receive_frame(observer.fd(), &mut receive_buffer)
            .unwrap_or_else(|error| panic!("privileged AF_PACKET E2E peer receive failed: {error}"))
        {
            if packet_type != PACKET_OUTGOING
                && length == expected.len()
                && receive_buffer[..length] == expected
            {
                println!("netns_e2e peer: observed the exact echoed frame on the host side");
                return;
            }
            if !poll_readable(observer.fd(), Instant::now()).unwrap_or_else(|error| {
                panic!("privileged AF_PACKET E2E peer poll failed: {error}")
            }) {
                break;
            }
        }
    }

    panic!(
        "timed out waiting for the exact echoed frame on host-side interface {interface_name:?}"
    );
}

fn configured_interface() -> String {
    match std::env::var("RUSTER_E2E_IFACE") {
        Ok(value) => value,
        Err(VarError::NotPresent) => DEFAULT_INTERFACE.to_owned(),
        Err(VarError::NotUnicode(_)) => {
            panic!("RUSTER_E2E_IFACE is not valid UTF-8")
        }
    }
}

fn interface_index(interface_name: &str) -> u32 {
    let c_name = CString::new(interface_name)
        .unwrap_or_else(|_| panic!("RUSTER_E2E_IFACE contains an embedded NUL byte"));
    // SAFETY: c_name is a live, NUL-terminated interface name.
    let if_index = unsafe { if_nametoindex(c_name.as_ptr()) };
    if if_index == 0 {
        let error = io::Error::last_os_error();
        panic!("cannot resolve interface {interface_name:?}: {error}");
    }
    if_index
}

fn system_page_size() -> usize {
    // SAFETY: sysconf has no borrowed pointer arguments.
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    usize::try_from(page_size)
        .unwrap_or_else(|_| panic!("sysconf(_SC_PAGESIZE) returned an invalid value {page_size}"))
}

fn expected_frame() -> [u8; FRAME_LEN] {
    let mut frame = [0_u8; FRAME_LEN];
    frame[..BROADCAST_MAC.len()].copy_from_slice(&BROADCAST_MAC);
    frame[BROADCAST_MAC.len()..BROADCAST_MAC.len() + SOURCE_MAC.len()].copy_from_slice(&SOURCE_MAC);
    frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
    for (index, byte) in frame[14..].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(3).wrapping_add(0x41);
    }
    frame
}

fn packet_address(if_index: u32, destination: Option<&[u8; 6]>) -> SockaddrLl {
    let mut sll_addr = [0_u8; 8];
    let sll_halen = if let Some(destination) = destination {
        sll_addr[..destination.len()].copy_from_slice(destination);
        6
    } else {
        0
    };
    SockaddrLl {
        sll_family: AF_PACKET as u16,
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: i32::try_from(if_index).expect("Linux interface index fits sockaddr_ll"),
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen,
        sll_addr,
    }
}

fn open_raw_socket(
    interface_name: &str,
    ignore_outgoing: bool,
) -> Result<RawPacketSocket, io::Error> {
    let if_index = interface_index(interface_name);
    // SAFETY: socket has no borrowed pointer arguments.
    let fd = unsafe {
        socket(
            AF_PACKET,
            SOCK_RAW | SOCK_CLOEXEC,
            c_int::from(ETH_P_ALL.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = RawPacketSocket { fd };

    if ignore_outgoing {
        let value: c_int = 1;
        // SAFETY: value is initialized and remains live for the syscall.
        let result = unsafe {
            setsockopt(
                socket.fd,
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                (&value as *const c_int).cast::<c_void>(),
                u32::try_from(size_of::<c_int>()).expect("c_int size fits socklen_t"),
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let address = packet_address(if_index, None);
    // SAFETY: address is a fully initialized sockaddr_ll and remains live for
    // the syscall.
    let result = unsafe {
        bind(
            socket.fd,
            (&address as *const SockaddrLl).cast::<c_void>(),
            u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t"),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn send_frame(fd: RawFd, address: &SockaddrLl, frame: &[u8]) -> Result<(), io::Error> {
    // SAFETY: frame and address are live for the duration of the syscall.
    let sent = unsafe {
        sendto(
            fd,
            frame.as_ptr().cast::<c_void>(),
            frame.len(),
            MSG_DONTWAIT,
            (address as *const SockaddrLl).cast::<c_void>(),
            u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t"),
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let sent = usize::try_from(sent).expect("successful sendto length is nonnegative");
    if sent != frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("sendto wrote {sent} bytes instead of {}", frame.len()),
        ));
    }
    Ok(())
}

fn poll_readable(fd: RawFd, deadline: Instant) -> Result<bool, io::Error> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut poll_fd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd is one initialized pollfd and remains live for the
        // duration of the syscall.
        let result = unsafe { poll(&mut poll_fd, 1, timeout) };
        if result > 0 {
            if poll_fd.revents & POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "poll reported POLLNVAL",
                ));
            }
            return Ok(poll_fd.revents & (POLLIN | POLLERR | POLLHUP) != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(EINTR) {
            continue;
        }
        return Err(error);
    }
}

fn receive_frame(fd: RawFd, buffer: &mut [u8]) -> Result<Option<(usize, u8)>, io::Error> {
    let mut address = SockaddrLl {
        sll_family: 0,
        sll_protocol: 0,
        sll_ifindex: 0,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let mut address_length =
        u32::try_from(size_of::<SockaddrLl>()).expect("sockaddr_ll size fits socklen_t");
    // SAFETY: buffer and address are initialized writable storage and remain
    // live for the duration of the syscall.
    let received = unsafe {
        recvfrom(
            fd,
            buffer.as_mut_ptr().cast::<c_void>(),
            buffer.len(),
            MSG_DONTWAIT,
            (&mut address as *mut SockaddrLl).cast::<c_void>(),
            &mut address_length,
        )
    };
    if received < 0 {
        let error = io::Error::last_os_error();
        if is_would_block(&error) {
            return Ok(None);
        }
        return Err(error);
    }
    let length = usize::try_from(received).expect("successful recvfrom length is nonnegative");
    Ok(Some((length, address.sll_pkttype)))
}

fn is_would_block(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(EAGAIN))
}

fn panic_platform_error(operation: &str, error: PlatformError) -> ! {
    if let PlatformError::Syscall { errno, .. } = error {
        if matches!(errno.get(), EPERM | EACCES) {
            panic!(
                "privileged E2E was requested but CAP_NET_RAW is unavailable ({operation}: {error})"
            );
        }
    }
    panic!("privileged AF_PACKET E2E {operation} failed: {error}");
}

fn panic_raw_socket_error(operation: &str, error: io::Error) -> ! {
    if matches!(error.raw_os_error(), Some(EPERM | EACCES)) {
        panic!(
            "privileged E2E was requested but CAP_NET_RAW is unavailable ({operation}: {error})"
        );
    }
    panic!("privileged AF_PACKET E2E {operation} failed: {error}");
}

unsafe extern "C" {
    fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
    fn setsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *const c_void,
        option_len: u32,
    ) -> c_int;
    fn bind(socket: c_int, address: *const c_void, address_len: u32) -> c_int;
    fn sendto(
        socket: c_int,
        buffer: *const c_void,
        length: usize,
        flags: c_int,
        address: *const c_void,
        address_len: u32,
    ) -> isize;
    fn recvfrom(
        socket: c_int,
        buffer: *mut c_void,
        length: usize,
        flags: c_int,
        address: *mut c_void,
        address_len: *mut u32,
    ) -> isize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
    fn if_nametoindex(ifname: *const c_char) -> u32;
    fn sysconf(name: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
}

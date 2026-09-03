#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
#![allow(unsafe_code)]

use std::{
    env::VarError,
    ffi::{c_char, c_int, c_void, CString},
    io,
    mem::size_of,
    os::fd::RawFd,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use ruster_core::{DropReason, IfId, PacketBatch, PacketIo};
use ruster_io_xdp_native::{
    abi::{XDP_COPY, XDP_USE_NEED_WAKEUP},
    ensure_supported, RingConfig, UmemConfig, ValidatedBindFlags, XdpAttachMode,
    XdpRedirectProgram, XdpResource, XdpResourceBuilder, XskMap,
};

const FRAME_SIZE: u32 = 2_048;
const FRAME_LEN: usize = 60;
const RING_ENTRIES: u32 = 2;
const RX_BUDGET: usize = 1;
const E2E_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_SLICE: Duration = Duration::from_millis(50);
const NO_PACKET_TIMEOUT: Duration = Duration::from_millis(50);

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
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_PRIVATE: c_int = 0x02;
const MAP_ANONYMOUS: c_int = 0x20;

const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const SOURCE_MAC: [u8; 6] = [0x02, 0x72, 0x75, 0x73, 0x74, 0x2a];

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
            let _ = close(self.fd);
        }
    }
}

struct AnonymousMemory {
    address: *mut u8,
    len: usize,
}

impl AnonymousMemory {
    fn new(len: usize) -> Result<Self, io::Error> {
        // SAFETY: the arguments request a private, writable anonymous mapping;
        // no caller pointer is dereferenced by mmap itself.
        let address = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if address.is_null() || address as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            address: address.cast(),
            len,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the mapping is live for the returned borrow and was created
        // with read/write permissions for exactly this byte extent.
        unsafe { std::slice::from_raw_parts_mut(self.address, self.len) }
    }
}

impl Drop for AnonymousMemory {
    fn drop(&mut self) {
        // SAFETY: this is the exact address and length returned by mmap, and
        // the mapping is unmapped at most once by this owner.
        let result = unsafe { munmap(self.address.cast(), self.len) };
        if result != 0 {
            eprintln!(
                "anonymous UMEM munmap failed: {}",
                io::Error::last_os_error()
            );
        }
    }
}

#[derive(Clone, Copy)]
enum CompletionAction {
    Recycle,
    Transmit,
}

#[test]
fn netns_xdp_e2e() {
    if !privileged_e2e_requested() {
        return;
    }

    let interface_name = required_interface("RUSTER_E2E_IFACE");
    let peer_name = required_interface("RUSTER_E2E_PEER_IFACE");
    ensure_supported().unwrap_or_else(|error| {
        panic!("privileged AF_XDP E2E platform validation failed: {error:?}")
    });

    let if_index = interface_index(&interface_name);
    let peer_if_index = interface_index(&peer_name);
    let interface = IfId(u16::try_from(if_index).expect("Linux interface index fits IfId"));
    assert!(
        !link_has_xdp(&interface_name),
        "interface already has XDP before test"
    );

    let page_size = system_page_size();
    let frame_size = usize::try_from(FRAME_SIZE).expect("frame size fits usize");
    assert_eq!(
        page_size % frame_size,
        0,
        "the reviewed UMEM frame size must divide the system page size"
    );
    let frame_count = u32::try_from((page_size * 2) / frame_size)
        .expect("page-aligned UMEM frame count fits u32");
    assert!(frame_count > 1, "UMEM must contain RX and generated frames");
    let umem_config = UmemConfig::new(frame_count, FRAME_SIZE, 0, 1, frame_count - 1, 0)
        .unwrap_or_else(|error| panic!("UmemConfig failed: {error:?}"));
    let rings = RingConfig::new(RING_ENTRIES, RING_ENTRIES, RING_ENTRIES, RING_ENTRIES)
        .unwrap_or_else(|error| panic!("RingConfig failed: {error:?}"));
    let bind_flags = ValidatedBindFlags::new(XDP_USE_NEED_WAKEUP | XDP_COPY)
        .unwrap_or_else(|error| panic!("bind flags failed: {error:?}"));
    assert_eq!(bind_flags.raw(), XDP_USE_NEED_WAKEUP | XDP_COPY);
    assert_eq!(umem_config.byte_len() as usize, page_size * 2);
    let umem_len = usize::try_from(umem_config.byte_len()).expect("UMEM length fits usize");

    // Preserve the existing low-level setup/ring-view coverage on a short-lived
    // resource. ring_views retires its owner from PacketIo, so the live resource
    // below deliberately uses only the authoritative data-path API.
    let mut control_memory = AnonymousMemory::new(umem_len)
        .unwrap_or_else(|error| panic!("anonymous UMEM mmap failed: {error}"));
    let mut control_resource = build_resource(
        control_memory.as_mut_slice(),
        umem_config,
        rings,
        if_index,
        bind_flags,
    );
    assert_eq!(control_resource.ifindex(), if_index);
    assert_eq!(control_resource.queue_id(), 0);
    {
        let views = control_resource
            .ring_views()
            .unwrap_or_else(|error| panic!("ring_views failed: {error:?}"));
        assert_eq!(views.fill.capacity(), RING_ENTRIES);
        assert_eq!(views.completion.capacity(), RING_ENTRIES);
        assert_eq!(views.rx.capacity(), RING_ENTRIES);
        assert_eq!(views.tx.capacity(), RING_ENTRIES);
    }
    control_resource
        .close()
        .unwrap_or_else(|error| panic!("control resource close failed: {error:?}"));
    drop(control_memory);

    let sender = open_raw_socket(&peer_name, false).unwrap_or_else(|error| {
        panic_raw_socket_error("peer AF_PACKET sender setup", error);
    });
    let observer = open_raw_socket(&peer_name, true).unwrap_or_else(|error| {
        panic_raw_socket_error("peer AF_PACKET observer setup", error);
    });
    let destination = packet_address(peer_if_index, Some(&BROADCAST_MAC));

    let mut umem_memory = AnonymousMemory::new(umem_len)
        .unwrap_or_else(|error| panic!("anonymous UMEM mmap failed: {error}"));
    let mut resource = build_resource(
        umem_memory.as_mut_slice(),
        umem_config,
        rings,
        if_index,
        bind_flags,
    );
    assert_eq!(resource.bind_flags(), bind_flags);

    let map = XskMap::new(1)
        .unwrap_or_else(|error| panic!("XSKMAP creation failed (permission is fatal): {error:?}"));
    assert_eq!(map.max_entries(), 1);
    map.register(&resource)
        .unwrap_or_else(|error| panic!("map register failed (permission is fatal): {error:?}"));
    let program = map.load_redirect_program().unwrap_or_else(|error| {
        panic!("load_redirect_program failed (permission is fatal): {error:?}")
    });
    assert_eq!(XdpRedirectProgram::instruction_count(), 7);
    assert_eq!(XdpRedirectProgram::bytecode_len(), 7 * 8);
    let mut attachment = program
        .attach_with_mode(if_index, XdpAttachMode::Skb)
        .unwrap_or_else(|error| panic!("attach failed (permission is fatal): {error:?}"));
    assert_eq!(attachment.ifindex(), if_index);
    assert_eq!(attachment.mode(), XdpAttachMode::Skb);
    assert!(attachment.is_attached());
    assert!(link_has_xdp(&interface_name));

    // With one RX chunk, the builder's initial fill publication supplies one
    // chunk. The peer packet below consumes it, making Fill empty while RX is
    // live. receive(0) must return an empty batch without waiting or failing.
    let first_frame = known_frame(0x11);
    send_frame_until(
        &sender,
        &destination,
        &first_frame,
        Instant::now() + E2E_TIMEOUT,
    );
    assert_live_fill_empty_receive_zero(&mut resource);
    receive_expected(
        &mut resource,
        None,
        &destination,
        &first_frame,
        CompletionAction::Recycle,
        interface,
        false,
    );

    // The recycled RX chunk must be refilled before this second frame arrives.
    let recycled_frame = known_frame(0x22);
    receive_expected(
        &mut resource,
        Some(&sender),
        &destination,
        &recycled_frame,
        CompletionAction::Recycle,
        interface,
        false,
    );

    // Every receive tick enforces the explicit budget, including the zero
    // budget exercised above. This frame also exercises the normal budget-1
    // path with a complete byte-for-byte payload assertion.
    let budget_frame = known_frame(0x33);
    receive_expected(
        &mut resource,
        Some(&sender),
        &destination,
        &budget_frame,
        CompletionAction::Recycle,
        interface,
        false,
    );

    // PacketLease::commit is the SlotCompletion::Transmit path. finish() must
    // publish TX, take the need-wakeup kick, and preserve accepted accounting.
    let transmit_frame = known_frame(0x44);
    receive_expected(
        &mut resource,
        Some(&sender),
        &destination,
        &transmit_frame,
        CompletionAction::Transmit,
        interface,
        false,
    );
    observe_exact_frame(&observer, &transmit_frame);

    // The only RX chunk is TX-owned until the kernel publishes its completion.
    // Re-sending is intentional: early AF_PACKET sends can be dropped while
    // Fill is empty. A successful exact receive proves CQ reclaim + Fill refill
    // happened before this chunk was reused.
    let reused_frame = known_frame(0x55);
    receive_expected(
        &mut resource,
        Some(&sender),
        &destination,
        &reused_frame,
        CompletionAction::Recycle,
        interface,
        true,
    );

    let wait_started = Instant::now();
    let ready = resource
        .wait_for_rx(NO_PACKET_TIMEOUT)
        .unwrap_or_else(|error| panic!("empty RX wait failed: {error:?}"));
    assert!(!ready, "empty veth RX wait unexpectedly reported readiness");
    assert!(
        wait_started.elapsed() < E2E_TIMEOUT,
        "empty RX wait exceeded its bounded timeout"
    );
    let mut empty_batch = resource
        .receive(RX_BUDGET)
        .unwrap_or_else(|error| panic!("empty RX receive failed: {error:?}"));
    assert!(empty_batch.next_packet().is_none());
    let empty_completion = empty_batch.finish();
    assert!(empty_completion.invariants_hold());
    assert!(empty_completion.error.is_none());

    drop(observer);
    drop(sender);
    attachment
        .detach()
        .unwrap_or_else(|error| panic!("detach failed: {error:?}"));
    assert!(!attachment.is_attached());
    assert!(!link_has_xdp(&interface_name));
    drop(attachment);
    program
        .close()
        .unwrap_or_else(|error| panic!("program close failed: {error:?}"));
    map.close()
        .unwrap_or_else(|error| panic!("map close failed: {error:?}"));
    resource
        .close()
        .unwrap_or_else(|error| panic!("resource close failed: {error:?}"));
    drop(umem_memory);
}

fn privileged_e2e_requested() -> bool {
    match std::env::var("RUSTER_PRIVILEGED_E2E") {
        Ok(value) if value == "1" => true,
        Ok(value) => {
            println!(
                "netns_xdp_e2e: skipped: RUSTER_PRIVILEGED_E2E={value:?}; set it to 1 to request the privileged E2E"
            );
            false
        }
        Err(VarError::NotPresent) => {
            println!(
                "netns_xdp_e2e: skipped: RUSTER_PRIVILEGED_E2E is unset; set it to 1 to request the privileged E2E"
            );
            false
        }
        Err(VarError::NotUnicode(_)) => {
            println!(
                "netns_xdp_e2e: skipped: RUSTER_PRIVILEGED_E2E is not valid UTF-8; set it to 1 to request the privileged E2E"
            );
            false
        }
    }
}

fn required_interface(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => panic!("{name} must not be empty for privileged AF_XDP E2E"),
        Err(VarError::NotPresent) => panic!("{name} is required for privileged AF_XDP E2E"),
        Err(VarError::NotUnicode(_)) => panic!("{name} is not valid UTF-8"),
    }
}

fn interface_index(interface_name: &str) -> u32 {
    let c_name = CString::new(interface_name)
        .unwrap_or_else(|_| panic!("{interface_name:?} contains an embedded NUL byte"));
    // SAFETY: c_name is a live, NUL-terminated interface name.
    let if_index = unsafe { if_nametoindex(c_name.as_ptr()) };
    if if_index == 0 {
        panic!(
            "cannot resolve interface {interface_name:?}: {}",
            io::Error::last_os_error()
        );
    }
    if_index
}

fn system_page_size() -> usize {
    // SAFETY: sysconf has no borrowed pointer arguments.
    let page_size = unsafe { sysconf(SC_PAGESIZE) };
    usize::try_from(page_size)
        .unwrap_or_else(|_| panic!("sysconf(_SC_PAGESIZE) returned {page_size}"))
}

fn build_resource<'umem>(
    memory: &'umem mut [u8],
    umem: UmemConfig,
    rings: RingConfig,
    if_index: u32,
    bind_flags: ValidatedBindFlags,
) -> XdpResource<'umem> {
    XdpResourceBuilder::new(umem, rings, if_index, 0)
        .unwrap_or_else(|error| panic!("builder failed: {error:?}"))
        .with_bind_flags(bind_flags)
        .build(memory)
        .unwrap_or_else(|error| {
            panic!("resource build failed (permission errors are fatal): {error:?}")
        })
}

fn link_has_xdp(interface_name: &str) -> bool {
    let output = Command::new("ip")
        .args(["-details", "link", "show", "dev", interface_name])
        .output()
        .unwrap_or_else(|error| panic!("ip link show failed: {error}"));
    assert!(
        output.status.success(),
        "ip link show failed for {interface_name:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.split_whitespace().any(|word| word == "prog/xdp"))
}

fn known_frame(tag: u8) -> [u8; FRAME_LEN] {
    let mut frame = [0_u8; FRAME_LEN];
    frame[..BROADCAST_MAC.len()].copy_from_slice(&BROADCAST_MAC);
    frame[BROADCAST_MAC.len()..BROADCAST_MAC.len() + SOURCE_MAC.len()].copy_from_slice(&SOURCE_MAC);
    frame[12..14].copy_from_slice(&0x88b5_u16.to_be_bytes());
    frame[14] = tag;
    for (index, byte) in frame[15..].iter_mut().enumerate() {
        *byte = tag.wrapping_add((index as u8).wrapping_mul(7));
    }
    frame
}

fn receive_expected(
    resource: &mut XdpResource<'_>,
    sender: Option<&RawPacketSocket>,
    destination: &SockaddrLl,
    expected: &[u8; FRAME_LEN],
    action: CompletionAction,
    egress: IfId,
    resend: bool,
) {
    let deadline = Instant::now() + E2E_TIMEOUT;
    let mut sent = false;
    loop {
        if let Some(sender) = sender {
            if resend || !sent {
                send_frame_until(sender, destination, expected, deadline);
                sent = true;
            }
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for the exact AF_XDP RX frame");
        }
        let _ = resource
            .wait_for_rx(remaining.min(POLL_SLICE))
            .unwrap_or_else(|error| panic!("wait_for_rx failed: {error:?}"));

        let mut batch = resource
            .receive(RX_BUDGET)
            .unwrap_or_else(|error| panic!("PacketIo::receive failed: {error:?}"));
        let mut slots = 0_usize;
        let mut matched = false;
        while let Some(mut lease) = batch.next_packet() {
            slots += 1;
            assert!(
                slots <= RX_BUDGET,
                "PacketIo::receive returned more than its budget: {slots} > {RX_BUDGET}"
            );
            assert_eq!(lease.ingress(), egress);
            let exact = lease.bytes_mut() == expected.as_slice();
            if exact {
                assert!(!matched, "the exact frame was delivered twice in one batch");
                matched = true;
                match action {
                    CompletionAction::Recycle => lease.recycle(DropReason::RouteMiss),
                    CompletionAction::Transmit => lease.commit(egress),
                }
            } else {
                lease.recycle(DropReason::RouteMiss);
            }
        }

        let completion = batch.finish();
        assert!(
            completion.invariants_hold(),
            "AF_XDP batch completion invariants failed: {completion:?}"
        );
        assert!(
            completion.error.is_none(),
            "AF_XDP batch completed with an error: {completion:?}"
        );
        if matched {
            match action {
                CompletionAction::Recycle => {
                    assert_eq!(completion.tx_requested, 0);
                    assert_eq!(completion.tx_accepted, 0);
                    assert_eq!(completion.tx_rejected, 0);
                    assert_eq!(completion.recycled, 1);
                }
                CompletionAction::Transmit => {
                    assert_eq!(completion.tx_requested, 1);
                    assert_eq!(completion.tx_accepted, 1);
                    assert_eq!(completion.tx_rejected, 0);
                    assert_eq!(completion.recycled, 0);
                }
            }
            return;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for the exact AF_XDP RX payload");
        }
    }
}

fn assert_live_fill_empty_receive_zero(resource: &mut XdpResource<'_>) {
    let deadline = Instant::now() + E2E_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for the live Fill-empty RX event");
        }
        if resource
            .wait_for_rx(remaining.min(POLL_SLICE))
            .unwrap_or_else(|error| panic!("Fill-empty wait_for_rx failed: {error:?}"))
        {
            break;
        }
    }

    let mut batch = resource
        .receive(0)
        .unwrap_or_else(|error| panic!("receive with live empty Fill failed: {error:?}"));
    assert!(batch.next_packet().is_none());
    let completion = batch.finish();
    assert!(
        completion.invariants_hold(),
        "Fill-empty zero-packet completion invariants failed: {completion:?}"
    );
    assert_eq!(completion.tx_requested, 0);
    assert_eq!(completion.tx_accepted, 0);
    assert_eq!(completion.tx_rejected, 0);
    assert_eq!(completion.recycled, 0);
    assert!(completion.error.is_none());
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

fn send_frame_until(
    socket: &RawPacketSocket,
    destination: &SockaddrLl,
    frame: &[u8; FRAME_LEN],
    deadline: Instant,
) {
    loop {
        match send_frame(socket.fd(), destination, frame) {
            Ok(()) => return,
            Err(error)
                if matches!(error.raw_os_error(), Some(EAGAIN) | Some(EINTR))
                    && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic_raw_socket_error("peer AF_PACKET send", error),
        }
    }
}

fn send_frame(
    fd: RawFd,
    destination: &SockaddrLl,
    frame: &[u8; FRAME_LEN],
) -> Result<(), io::Error> {
    // SAFETY: frame and destination are live for the duration of the syscall.
    let sent = unsafe {
        sendto(
            fd,
            frame.as_ptr().cast::<c_void>(),
            frame.len(),
            MSG_DONTWAIT,
            (destination as *const SockaddrLl).cast::<c_void>(),
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

fn observe_exact_frame(observer: &RawPacketSocket, expected: &[u8; FRAME_LEN]) {
    let deadline = Instant::now() + E2E_TIMEOUT;
    let mut buffer = [0_u8; 2_048];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for the exact AF_XDP TX frame on the peer");
        }
        if !poll_readable(observer.fd(), remaining.min(POLL_SLICE))
            .unwrap_or_else(|error| panic!("peer AF_PACKET poll failed: {error}"))
        {
            continue;
        }
        while let Some((length, packet_type)) = receive_frame(observer.fd(), &mut buffer)
            .unwrap_or_else(|error| panic!("peer AF_PACKET receive failed: {error}"))
        {
            if packet_type != PACKET_OUTGOING
                && length == expected.len()
                && buffer[..length] == expected[..]
            {
                return;
            }
            if !poll_readable(observer.fd(), Duration::from_millis(0))
                .unwrap_or_else(|error| panic!("peer AF_PACKET poll failed: {error}"))
            {
                break;
            }
        }
    }
}

fn poll_readable(fd: RawFd, timeout: Duration) -> Result<bool, io::Error> {
    loop {
        let timeout_millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut poll_fd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: poll_fd is one initialized pollfd and remains live for the
        // duration of the syscall.
        let result = unsafe { poll(&mut poll_fd, 1, timeout_millis) };
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
        if error.raw_os_error() == Some(EAGAIN) {
            return Ok(None);
        }
        return Err(error);
    }
    let length = usize::try_from(received).expect("successful recvfrom length is nonnegative");
    Ok(Some((length, address.sll_pkttype)))
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
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> c_int;
    fn close(fd: c_int) -> c_int;
}

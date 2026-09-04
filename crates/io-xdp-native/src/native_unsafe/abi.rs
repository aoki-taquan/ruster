//! Linux AF_XDP UAPI facts and checked ring-map layout arithmetic.
//!
//! Values and C layouts are pinned to Linux v6.8
//! `include/uapi/linux/if_xdp.h`. This module deliberately performs no FFI,
//! pointer access, socket operation, or memory mapping and therefore contains
//! no unsafe code.

use std::mem::{align_of, offset_of, size_of};

use crate::{AbiLayoutError, RingEntries, RingField};

/// Pinned source of the C ABI facts in this module.
pub const ABI_HEADER_PROFILE: &str = "Linux v6.8 include/uapi/linux/if_xdp.h";
/// Exact UAPI source for `struct sockaddr_xdp`.
pub const ABI_SOCKADDR_XDP_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/if_xdp.h:48-54";
/// Exact UAPI source for the ring offset structures.
pub const ABI_RING_OFFSETS_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/if_xdp.h:59-71";
/// Exact UAPI source for `struct xdp_umem_reg`.
pub const ABI_UMEM_REG_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/if_xdp.h:83-90";

/// Pinned source of the reviewed eBPF UAPI facts in this module.
pub const BPF_ABI_HEADER_PROFILE: &str =
    "Linux v6.8 include/uapi/linux/bpf.h and x86_64 unistd_64.h";
/// Exact x86_64 syscall-number source for `__NR_bpf`.
pub const BPF_SYSCALL_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137-generic/arch/x86/include/generated/uapi/asm/unistd_64.h:325";
/// Exact UAPI source for the map commands used by the XSKMAP seam.
pub const BPF_COMMAND_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:883-887";
/// Exact UAPI source for the XSKMAP map type enumerator.
pub const BPF_MAP_TYPE_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:923-942";
/// Exact UAPI source for the reviewed `union bpf_attr` variants and extent.
pub const BPF_ATTR_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:1398-1738";
/// Exact UAPI source for the eBPF instruction layout and register numbers.
pub const BPF_INSN_SOURCE: &str = "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:53-78";
/// Exact UAPI source for the eBPF instruction-class/field values included by
/// `linux/bpf.h`.
pub const BPF_COMMON_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf_common.h:5-27,44-51 (included by bpf.h:11-12)";
/// Exact UAPI source for the program-load command and XDP program type.
pub const BPF_PROGRAM_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:883-890,981-989";
/// Exact UAPI source for the map-fd pseudo-instruction extension.
pub const BPF_PSEUDO_MAP_FD_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:1246-1258";
/// Exact UAPI source for the `BPF_PROG_LOAD` attribute fields.
pub const BPF_PROG_LOAD_ATTR_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:1456-1495";
/// Exact UAPI source for the XDP return values and `struct xdp_md` fields.
pub const XDP_PROGRAM_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:6335-6360";
/// Exact UAPI source for the redirect-map helper id and signature.
pub const BPF_REDIRECT_MAP_SOURCE: &str =
    "/usr/src/linux-headers-6.8.0-137/include/uapi/linux/bpf.h:2831-2854,5705-5758";

/// x86_64 Linux `__NR_bpf`.
pub const BPF_SYSCALL_NUMBER: i32 = 321;
/// `BPF_MAP_CREATE`, the first member of `enum bpf_cmd`.
pub const BPF_MAP_CREATE: u32 = 0;
/// `BPF_MAP_UPDATE_ELEM`, the third member of `enum bpf_cmd`.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// `BPF_PROG_LOAD`, the sixth member of `enum bpf_cmd`.
pub const BPF_PROG_LOAD: u32 = 5;
/// `BPF_PROG_TYPE_XDP`, the seventh member of `enum bpf_prog_type`.
pub const BPF_PROG_TYPE_XDP: u32 = 6;
/// `BPF_MAP_TYPE_XSKMAP`, the eighteenth member of `enum bpf_map_type`.
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
/// `BPF_ANY`, which creates or replaces an XSKMAP element.
pub const BPF_ANY: u64 = 0;
/// XSKMAP queue-id key width required by the UAPI map implementation.
pub const BPF_XSKMAP_KEY_SIZE: u32 = 4;
/// XSKMAP socket-fd value width required by the UAPI map implementation.
pub const BPF_XSKMAP_VALUE_SIZE: u32 = 4;

// The following values are copied from the reviewed Linux UAPI definitions,
// rather than inferred from an eBPF assembler. `BPF_LD`, `BPF_LDX`, `BPF_W`,
// `BPF_MEM`, `BPF_IMM`, `BPF_ALU64`, `BPF_MOV`, `BPF_X`, and `BPF_JMP` are
// defined in bpf_common.h (included by bpf.h at line 12); BPF_CALL and
// BPF_EXIT are defined directly in bpf.h. The low/high nibbles in a
// `bpf_insn` register byte are encoded by [`crate::BpfInsn`].
/// `BPF_LD` instruction class; `bpf_common.h:5-14`.
pub const BPF_LD: u8 = 0x00;
/// `BPF_LDX` instruction class; `bpf_common.h:5-14`.
pub const BPF_LDX: u8 = 0x01;
/// 32-bit load size `BPF_W`; `bpf_common.h:16-21`.
pub const BPF_W: u8 = 0x00;
/// Memory addressing mode `BPF_MEM`; `bpf_common.h:22-28`.
pub const BPF_MEM: u8 = 0x60;
/// Immediate source selector `BPF_K`; `bpf_common.h:49-51`.
pub const BPF_K: u8 = 0x00;
/// Register source selector `BPF_X`; `bpf_common.h:49-51`.
pub const BPF_X: u8 = 0x08;
/// 64-bit ALU instruction class; `bpf.h:16-18`.
pub const BPF_ALU64: u8 = 0x07;
/// Register-to-register move operation; `bpf.h:26-28`.
pub const BPF_MOV: u8 = 0xb0;
/// Jump instruction class; `bpf_common.h:5-14`.
pub const BPF_JMP: u8 = 0x05;
/// Helper-call operation; `bpf.h:37-46`.
pub const BPF_CALL: u8 = 0x80;
/// Program-exit operation; `bpf.h:37-46`.
pub const BPF_EXIT: u8 = 0x90;
/// Double-word immediate load size `BPF_DW`; `bpf.h:20-23`.
pub const BPF_DW: u8 = 0x18;
/// Immediate load mode `BPF_IMM`; `bpf_common.h:22-28`.
pub const BPF_IMM: u8 = 0x00;
/// Pseudo source-register value for a map fd load; `bpf.h:1246-1258`.
pub const BPF_PSEUDO_MAP_FD: u8 = 1;
/// `bpf_redirect_map` helper id; `bpf.h:5757` and `5926-5933`.
pub const BPF_FUNC_REDIRECT_MAP: i32 = 51;
/// XDP_PASS return action; `bpf.h:6335-6346`.
pub const XDP_PASS: u32 = 2;
/// `struct xdp_md::rx_queue_index` byte offset; `bpf.h:6351-6360`.
pub const XDP_MD_RX_QUEUE_INDEX_OFFSET: i16 = 16;

/// eBPF register numbers from `enum` at `bpf.h:53-67`.
pub const BPF_REG_0: u8 = 0;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_1: u8 = 1;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_2: u8 = 2;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_3: u8 = 3;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_4: u8 = 4;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_5: u8 = 5;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_6: u8 = 6;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_7: u8 = 7;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_8: u8 = 8;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_9: u8 = 9;
/// eBPF register number from `bpf.h:53-67`.
pub const BPF_REG_10: u8 = 10;
/// C ABI size of the full `union bpf_attr` on the reviewed x86_64 profile.
///
/// The union is defined at [`BPF_ATTR_SOURCE`]. Its 144-byte extent is the
/// `sizeof(union bpf_attr)` result of compiling that header for x86_64 Linux;
/// the native seam zero-fills all bytes before selecting a command variant.
pub const BPF_ATTR_SIZE: usize = 144;

/// AF_XDP protocol family.
pub const AF_XDP: i32 = 44;
/// AF_XDP socket option level.
pub const SOL_XDP: i32 = 283;

/// Share an existing UMEM.
pub const XDP_SHARED_UMEM: u16 = 1 << 0;
/// Require copy mode.
pub const XDP_COPY: u16 = 1 << 1;
/// Require zero-copy mode.
pub const XDP_ZEROCOPY: u16 = 1 << 2;
/// Enable conditional producer wakeups.
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;
/// Enable scatter/gather packets; deferred by the initial profile.
pub const XDP_USE_SG: u16 = 1 << 4;
/// Bind flags accepted by the initial profile.
pub const XDP_SUPPORTED_BIND_FLAGS: u16 =
    XDP_SHARED_UMEM | XDP_COPY | XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

/// Use unaligned UMEM chunks.
pub const XDP_UMEM_UNALIGNED_CHUNK_FLAG: u32 = 1 << 0;
/// Force software TX checksum in copy mode.
pub const XDP_UMEM_TX_SW_CSUM: u32 = 1 << 1;

/// Producer needs an explicit wakeup.
pub const XDP_RING_NEED_WAKEUP: u32 = 1 << 0;

/// Retrieve kernel ring offsets.
pub const XDP_MMAP_OFFSETS: i32 = 1;
/// Configure the RX ring.
pub const XDP_RX_RING: i32 = 2;
/// Configure the TX ring.
pub const XDP_TX_RING: i32 = 3;
/// Register UMEM.
pub const XDP_UMEM_REG: i32 = 4;
/// Configure the UMEM Fill ring.
pub const XDP_UMEM_FILL_RING: i32 = 5;
/// Configure the UMEM Completion ring.
pub const XDP_UMEM_COMPLETION_RING: i32 = 6;
/// Retrieve socket statistics.
pub const XDP_STATISTICS: i32 = 7;
/// Retrieve negotiated socket options.
pub const XDP_OPTIONS: i32 = 8;
/// Negotiated zero-copy option bit.
pub const XDP_OPTIONS_ZEROCOPY: u32 = 1 << 0;

/// RX ring mmap offset.
pub const XDP_PGOFF_RX_RING: u64 = 0;
/// TX ring mmap offset.
pub const XDP_PGOFF_TX_RING: u64 = 0x8000_0000;
/// UMEM Fill ring mmap offset.
pub const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x1_0000_0000;
/// UMEM Completion ring mmap offset.
pub const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x1_8000_0000;

/// A packet continues in the next descriptor; unsupported initially.
pub const XDP_PKT_CONTD: u32 = 1 << 0;
/// A TX packet carries metadata; unsupported initially.
pub const XDP_TX_METADATA: u32 = 1 << 1;

/// Linux `struct sockaddr_xdp`, verified against [`ABI_SOCKADDR_XDP_SOURCE`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SockAddrXdp {
    /// Protocol family; must be [`AF_XDP`].
    pub family: u16,
    /// `XDP_*` bind flags.
    pub flags: u16,
    /// Linux interface index.
    pub ifindex: u32,
    /// Hardware queue identifier.
    pub queue_id: u32,
    /// Owner socket fd when sharing UMEM.
    pub shared_umem_fd: u32,
}

/// Linux `struct xdp_ring_offset`, verified against [`ABI_RING_OFFSETS_SOURCE`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpRingOffset {
    /// Producer cursor byte offset.
    pub producer: u64,
    /// Consumer cursor byte offset.
    pub consumer: u64,
    /// Descriptor-array byte offset.
    pub descriptors: u64,
    /// Ring-flags byte offset.
    pub flags: u64,
}

/// Linux `struct xdp_mmap_offsets`, verified against [`ABI_RING_OFFSETS_SOURCE`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpMmapOffsets {
    /// RX ring offsets.
    pub rx: XdpRingOffset,
    /// TX ring offsets.
    pub tx: XdpRingOffset,
    /// Fill ring offsets.
    pub fill: XdpRingOffset,
    /// Completion ring offsets.
    pub completion: XdpRingOffset,
}

/// Linux `struct xdp_umem_reg`, verified against [`ABI_UMEM_REG_SOURCE`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpUmemReg {
    /// UAPI `addr`: start of the packet data area.
    pub address: u64,
    /// UAPI `len`: packet data area length.
    pub len: u64,
    /// UAPI `chunk_size`: fixed chunk size.
    pub chunk_size: u32,
    /// UAPI `headroom`: configured headroom before packet data.
    pub headroom: u32,
    /// UAPI `flags`: UMEM option flags.
    pub flags: u32,
    /// UAPI `tx_metadata_len`: per-chunk TX metadata length.
    pub tx_metadata_len: u32,
}

// These assertions are compile-time guards for the field order used by the
// dependency-free byte encoders below. The field definitions are sourced from
// `/usr/src/linux-headers-6.8.0-137/include/uapi/linux/if_xdp.h:83-90`;
// offsets are obtained from Rust's C-layout calculation, never guessed.
const _: [(); 32] = [(); size_of::<XdpUmemReg>()];
const _: [(); 8] = [(); align_of::<XdpUmemReg>()];
const _: [(); 0] = [(); offset_of!(XdpUmemReg, address)];
const _: [(); 8] = [(); offset_of!(XdpUmemReg, len)];
const _: [(); 16] = [(); offset_of!(XdpUmemReg, chunk_size)];
const _: [(); 20] = [(); offset_of!(XdpUmemReg, headroom)];
const _: [(); 24] = [(); offset_of!(XdpUmemReg, flags)];
const _: [(); 28] = [(); offset_of!(XdpUmemReg, tx_metadata_len)];

const _: [(); 16] = [(); size_of::<SockAddrXdp>()];
const _: [(); 0] = [(); offset_of!(SockAddrXdp, family)];
const _: [(); 2] = [(); offset_of!(SockAddrXdp, flags)];
const _: [(); 4] = [(); offset_of!(SockAddrXdp, ifindex)];
const _: [(); 8] = [(); offset_of!(SockAddrXdp, queue_id)];
const _: [(); 12] = [(); offset_of!(SockAddrXdp, shared_umem_fd)];

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + size_of::<u16>()].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_ne_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_ne_bytes());
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        bytes[offset..offset + size_of::<u64>()]
            .try_into()
            .expect("checked C-layout field extent"),
    )
}

/// Encodes `struct xdp_umem_reg` using its checked C-layout field offsets.
pub(crate) fn encode_xdp_umem_reg(value: XdpUmemReg) -> [u8; size_of::<XdpUmemReg>()] {
    let mut bytes = [0_u8; size_of::<XdpUmemReg>()];
    write_u64(&mut bytes, offset_of!(XdpUmemReg, address), value.address);
    write_u64(&mut bytes, offset_of!(XdpUmemReg, len), value.len);
    write_u32(
        &mut bytes,
        offset_of!(XdpUmemReg, chunk_size),
        value.chunk_size,
    );
    write_u32(&mut bytes, offset_of!(XdpUmemReg, headroom), value.headroom);
    write_u32(&mut bytes, offset_of!(XdpUmemReg, flags), value.flags);
    write_u32(
        &mut bytes,
        offset_of!(XdpUmemReg, tx_metadata_len),
        value.tx_metadata_len,
    );
    bytes
}

/// Encodes `struct sockaddr_xdp` using its checked C-layout field offsets.
pub(crate) fn encode_sockaddr_xdp(value: SockAddrXdp) -> [u8; size_of::<SockAddrXdp>()] {
    let mut bytes = [0_u8; size_of::<SockAddrXdp>()];
    write_u16(&mut bytes, offset_of!(SockAddrXdp, family), value.family);
    write_u16(&mut bytes, offset_of!(SockAddrXdp, flags), value.flags);
    write_u32(&mut bytes, offset_of!(SockAddrXdp, ifindex), value.ifindex);
    write_u32(
        &mut bytes,
        offset_of!(SockAddrXdp, queue_id),
        value.queue_id,
    );
    write_u32(
        &mut bytes,
        offset_of!(SockAddrXdp, shared_umem_fd),
        value.shared_umem_fd,
    );
    bytes
}

#[cfg(test)]
fn encode_ring_offset(bytes: &mut [u8], base: usize, value: XdpRingOffset) {
    write_u64(
        bytes,
        base + offset_of!(XdpRingOffset, producer),
        value.producer,
    );
    write_u64(
        bytes,
        base + offset_of!(XdpRingOffset, consumer),
        value.consumer,
    );
    write_u64(
        bytes,
        base + offset_of!(XdpRingOffset, descriptors),
        value.descriptors,
    );
    write_u64(bytes, base + offset_of!(XdpRingOffset, flags), value.flags);
}

/// Encodes a kernel-shaped `struct xdp_mmap_offsets` for seam tests.
#[cfg(test)]
pub(crate) fn encode_xdp_mmap_offsets(value: XdpMmapOffsets) -> [u8; size_of::<XdpMmapOffsets>()] {
    let mut bytes = [0_u8; size_of::<XdpMmapOffsets>()];
    encode_ring_offset(&mut bytes, offset_of!(XdpMmapOffsets, rx), value.rx);
    encode_ring_offset(&mut bytes, offset_of!(XdpMmapOffsets, tx), value.tx);
    encode_ring_offset(&mut bytes, offset_of!(XdpMmapOffsets, fill), value.fill);
    encode_ring_offset(
        &mut bytes,
        offset_of!(XdpMmapOffsets, completion),
        value.completion,
    );
    bytes
}

fn decode_ring_offset(bytes: &[u8], base: usize) -> XdpRingOffset {
    XdpRingOffset {
        producer: read_u64(bytes, base + offset_of!(XdpRingOffset, producer)),
        consumer: read_u64(bytes, base + offset_of!(XdpRingOffset, consumer)),
        descriptors: read_u64(bytes, base + offset_of!(XdpRingOffset, descriptors)),
        flags: read_u64(bytes, base + offset_of!(XdpRingOffset, flags)),
    }
}

/// Decodes a complete kernel `struct xdp_mmap_offsets` value.
pub(crate) fn decode_xdp_mmap_offsets(bytes: &[u8]) -> Option<XdpMmapOffsets> {
    if bytes.len() < size_of::<XdpMmapOffsets>() {
        return None;
    }
    Some(XdpMmapOffsets {
        rx: decode_ring_offset(bytes, offset_of!(XdpMmapOffsets, rx)),
        tx: decode_ring_offset(bytes, offset_of!(XdpMmapOffsets, tx)),
        fill: decode_ring_offset(bytes, offset_of!(XdpMmapOffsets, fill)),
        completion: decode_ring_offset(bytes, offset_of!(XdpMmapOffsets, completion)),
    })
}

/// Linux `struct xdp_statistics`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpStatistics {
    /// Packets dropped for reasons other than invalid descriptors.
    pub rx_dropped: u64,
    /// Invalid RX descriptors.
    pub rx_invalid_descriptors: u64,
    /// Invalid TX descriptors.
    pub tx_invalid_descriptors: u64,
    /// Packets dropped because the RX ring was full.
    pub rx_ring_full: u64,
    /// Failed Fill-ring descriptor retrievals.
    pub rx_fill_ring_empty_descriptors: u64,
    /// Failed TX-ring descriptor retrievals.
    pub tx_ring_empty_descriptors: u64,
}

/// Linux `struct xdp_options`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpOptions {
    /// Negotiated option bits.
    pub flags: u32,
}

/// Linux `struct xdp_desc`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpDescriptor {
    /// UMEM-relative packet address.
    pub address: u64,
    /// Visible packet length.
    pub len: u32,
    /// Descriptor option bits.
    pub options: u32,
}

/// Descriptor element stored by one native ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingElement {
    /// Fill and Completion rings contain one UMEM address.
    UmemAddress,
    /// RX and TX rings contain one [`XdpDescriptor`].
    PacketDescriptor,
}

impl RingElement {
    const fn size(self) -> usize {
        match self {
            Self::UmemAddress => size_of::<u64>(),
            Self::PacketDescriptor => size_of::<XdpDescriptor>(),
        }
    }

    const fn alignment(self) -> usize {
        match self {
            Self::UmemAddress => align_of::<u64>(),
            Self::PacketDescriptor => align_of::<XdpDescriptor>(),
        }
    }
}

/// Checked process-relative offsets and required mmap byte length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingMmapLayout {
    producer: usize,
    consumer: usize,
    flags: usize,
    descriptors: usize,
    byte_len: usize,
}

impl RingMmapLayout {
    /// Validates kernel-reported offsets before any future mmap pointer access.
    pub fn new(
        raw: XdpRingOffset,
        entries: RingEntries,
        element: RingElement,
    ) -> Result<Self, AbiLayoutError> {
        let fields = [
            checked_extent(
                RingField::Producer,
                raw.producer,
                size_of::<u32>(),
                align_of::<u32>(),
            )?,
            checked_extent(
                RingField::Consumer,
                raw.consumer,
                size_of::<u32>(),
                align_of::<u32>(),
            )?,
            checked_extent(
                RingField::Flags,
                raw.flags,
                size_of::<u32>(),
                align_of::<u32>(),
            )?,
            checked_extent(
                RingField::Descriptors,
                raw.descriptors,
                element.size().checked_mul(entries.get() as usize).ok_or(
                    AbiLayoutError::ExtentOverflow {
                        field: RingField::Descriptors,
                    },
                )?,
                element.alignment(),
            )?,
        ];

        for (index, first) in fields.iter().enumerate() {
            for second in &fields[index + 1..] {
                if first.start < second.end && second.start < first.end {
                    return Err(AbiLayoutError::OverlappingFields {
                        first: first.field,
                        second: second.field,
                    });
                }
            }
        }

        let byte_len = fields
            .iter()
            .map(|extent| extent.end)
            .max()
            .expect("four ring fields");
        Ok(Self {
            producer: usize::try_from(raw.producer)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            consumer: usize::try_from(raw.consumer)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            flags: usize::try_from(raw.flags).map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            descriptors: usize::try_from(raw.descriptors)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
            byte_len: usize::try_from(byte_len)
                .map_err(|_| AbiLayoutError::ExtentDoesNotFitUsize)?,
        })
    }

    /// Returns the producer cursor offset.
    #[must_use]
    pub const fn producer(self) -> usize {
        self.producer
    }

    /// Returns the consumer cursor offset.
    #[must_use]
    pub const fn consumer(self) -> usize {
        self.consumer
    }

    /// Returns the flags-word offset.
    #[must_use]
    pub const fn flags(self) -> usize {
        self.flags
    }

    /// Returns the descriptor-array offset.
    #[must_use]
    pub const fn descriptors(self) -> usize {
        self.descriptors
    }

    /// Returns the minimum required mmap byte length.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        self.byte_len
    }
}

#[derive(Clone, Copy)]
struct Extent {
    field: RingField,
    start: u64,
    end: u64,
}

fn checked_extent(
    field: RingField,
    offset: u64,
    len: usize,
    alignment: usize,
) -> Result<Extent, AbiLayoutError> {
    if !offset.is_multiple_of(alignment as u64) {
        return Err(AbiLayoutError::MisalignedOffset {
            field,
            offset,
            alignment,
        });
    }
    let len = u64::try_from(len).map_err(|_| AbiLayoutError::ExtentOverflow { field })?;
    let end = offset
        .checked_add(len)
        .ok_or(AbiLayoutError::ExtentOverflow { field })?;
    Ok(Extent {
        field,
        start: offset,
        end,
    })
}

#[cfg(test)]
mod tests {
    use crate::RingName;

    use super::*;

    #[test]
    fn abi_flag_masks_preserve_each_independent_bit() {
        // Protects the UAPI bit shifts and the bind-mask OR operations from
        // silently dropping one of the independently meaningful flags.
        assert_eq!(XDP_SHARED_UMEM, 1);
        assert_eq!(XDP_COPY, 2);
        assert_eq!(XDP_ZEROCOPY, 4);
        assert_eq!(XDP_USE_NEED_WAKEUP, 8);
        assert_eq!(XDP_USE_SG, 16);
        assert_eq!(XDP_SUPPORTED_BIND_FLAGS, 1 | 2 | 4 | 8);
        assert_eq!(XDP_UMEM_UNALIGNED_CHUNK_FLAG, 1);
        assert_eq!(XDP_UMEM_TX_SW_CSUM, 2);
        assert_eq!(XDP_OPTIONS_ZEROCOPY, 1);
        assert_eq!(XDP_PKT_CONTD, 1);
        assert_eq!(XDP_TX_METADATA, 2);
    }

    #[test]
    fn abi_encoders_write_every_c_layout_field() {
        // Protects the field writers and zero-initialized encoders: every
        // native-endian byte must come from the corresponding UAPI field.
        let umem = XdpUmemReg {
            address: 0x0102_0304_0506_0708,
            len: 0x1112_1314_1516_1718,
            chunk_size: 0x2122_2324,
            headroom: 0x3132_3334,
            flags: 0x4142_4344,
            tx_metadata_len: 0x5152_5354,
        };
        let mut expected = [0_u8; size_of::<XdpUmemReg>()];
        expected[0..8].copy_from_slice(&umem.address.to_ne_bytes());
        expected[8..16].copy_from_slice(&umem.len.to_ne_bytes());
        expected[16..20].copy_from_slice(&umem.chunk_size.to_ne_bytes());
        expected[20..24].copy_from_slice(&umem.headroom.to_ne_bytes());
        expected[24..28].copy_from_slice(&umem.flags.to_ne_bytes());
        expected[28..32].copy_from_slice(&umem.tx_metadata_len.to_ne_bytes());
        assert_eq!(encode_xdp_umem_reg(umem), expected);

        let sockaddr = SockAddrXdp {
            family: 0x0102,
            flags: 0x0304,
            ifindex: 0x0506_0708,
            queue_id: 0x090a_0b0c,
            shared_umem_fd: 0x0d0e_0f10,
        };
        let mut expected = [0_u8; size_of::<SockAddrXdp>()];
        expected[0..2].copy_from_slice(&sockaddr.family.to_ne_bytes());
        expected[2..4].copy_from_slice(&sockaddr.flags.to_ne_bytes());
        expected[4..8].copy_from_slice(&sockaddr.ifindex.to_ne_bytes());
        expected[8..12].copy_from_slice(&sockaddr.queue_id.to_ne_bytes());
        expected[12..16].copy_from_slice(&sockaddr.shared_umem_fd.to_ne_bytes());
        assert_eq!(encode_sockaddr_xdp(sockaddr), expected);
    }

    #[test]
    fn abi_mmap_offsets_decode_all_rings_at_distinct_bases() {
        // Protects decode offset addition: each ring and each field must be
        // read from its own C-layout base, rather than from a shifted address.
        let offsets = XdpMmapOffsets {
            rx: XdpRingOffset {
                producer: 1,
                consumer: 2,
                descriptors: 3,
                flags: 4,
            },
            tx: XdpRingOffset {
                producer: 11,
                consumer: 12,
                descriptors: 13,
                flags: 14,
            },
            fill: XdpRingOffset {
                producer: 21,
                consumer: 22,
                descriptors: 23,
                flags: 24,
            },
            completion: XdpRingOffset {
                producer: 31,
                consumer: 32,
                descriptors: 33,
                flags: 34,
            },
        };
        assert_eq!(
            decode_xdp_mmap_offsets(&encode_xdp_mmap_offsets(offsets)),
            Some(offsets)
        );
    }

    #[test]
    fn abi_mmap_offsets_require_the_complete_kernel_struct() {
        // Protects the length boundary: a truncated getsockopt result must be
        // rejected, while an exact result is accepted.
        let bytes = encode_xdp_mmap_offsets(XdpMmapOffsets::default());
        assert_eq!(decode_xdp_mmap_offsets(&bytes[..bytes.len() - 1]), None);
        assert_eq!(
            decode_xdp_mmap_offsets(&bytes),
            Some(XdpMmapOffsets::default())
        );
        assert_eq!(
            decode_xdp_mmap_offsets(&[0_u8; size_of::<XdpMmapOffsets>() + 1]),
            Some(XdpMmapOffsets::default())
        );
    }

    #[test]
    fn abi_layout_checks_descriptor_alignment_and_keeps_nonzero_accessors() {
        // Protects descriptor alignment validation and the producer accessor;
        // both cases are otherwise easy to mask with zero-valued fixtures.
        let entries = RingEntries::new(RingName::Rx, 1).expect("valid entries");
        let raw = XdpRingOffset {
            producer: 4,
            consumer: 64,
            flags: 128,
            descriptors: 196,
        };
        assert_eq!(
            RingMmapLayout::new(raw, entries, RingElement::UmemAddress),
            Err(AbiLayoutError::MisalignedOffset {
                field: RingField::Descriptors,
                offset: 196,
                alignment: 8,
            })
        );

        let valid = RingMmapLayout::new(
            XdpRingOffset {
                descriptors: 200,
                ..raw
            },
            entries,
            RingElement::UmemAddress,
        )
        .expect("non-overlapping aligned layout");
        assert_eq!(valid.producer(), 4);
        assert_eq!(valid.consumer(), 64);
        assert_eq!(valid.flags(), 128);
        assert_eq!(valid.descriptors(), 200);
        assert_eq!(valid.byte_len(), 208);
    }
}

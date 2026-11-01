//! Hand-assembled XDP redirect program and pinned BPF UAPI constants (X00D).
//!
//! This module is pure data: it never calls the kernel. The private syscall
//! seam loads [`redirect_program`] with `BPF_PROG_LOAD`. Every constant is
//! pinned to Linux v6.8 `include/uapi/linux/bpf.h`, `bpf_common.h`, and
//! `if_link.h`; each value is unchanged since Linux 5.9, the minimum kernel
//! of the `bpf_link` attach profile.
//!
//! The program is original work under the repository license. Its eBPF
//! semantics are:
//!
//! ```text
//! 0: r2 = *(u32 *)(r1 + 16)   ; r2 = ctx->rx_queue_index
//! 1: r1 = map_fd ll           ; ld_imm64, src_reg BPF_PSEUDO_MAP_FD (two slots)
//! 3: r3 = 2                   ; XDP_PASS: action if the XSKMAP slot is empty
//! 4: call 51                  ; r0 = bpf_redirect_map(r1, r2, r3)
//! 5: exit                     ; return r0
//! ```

#![cfg_attr(
    not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )),
    allow(dead_code)
)]

use std::ffi::CStr;

/// One `struct bpf_insn`: `code`, `dst_reg:4`/`src_reg:4`, `off`, `imm`.
///
/// On little-endian x86_64 the C bitfield places `dst_reg` in the low nibble
/// of the second byte, so `regs = dst | src << 4`. The `repr(C)` layout is
/// exactly the kernel's 8-byte instruction (checked below).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct BpfInsn {
    pub(crate) code: u8,
    pub(crate) regs: u8,
    pub(crate) off: i16,
    pub(crate) imm: i32,
}

const _: [(); 8] = [(); std::mem::size_of::<BpfInsn>()];
const _: [(); 4] = [(); std::mem::align_of::<BpfInsn>()];

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        assert!(dst <= 10 && src <= 10, "eBPF has registers r0..=r10");
        Self {
            code,
            regs: dst | (src << 4),
            off,
            imm,
        }
    }

    /// Little-endian wire bytes, as the kernel reads them on x86_64.
    #[cfg(test)]
    pub(crate) fn to_le_bytes(self) -> [u8; 8] {
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code, self.regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ]
    }
}

// Instruction classes, sizes, modes, and operations (`bpf_common.h`, `bpf.h`).
pub(crate) const BPF_LD: u8 = 0x00;
pub(crate) const BPF_LDX: u8 = 0x01;
pub(crate) const BPF_JMP: u8 = 0x05;
pub(crate) const BPF_ALU64: u8 = 0x07;
pub(crate) const BPF_W: u8 = 0x00;
pub(crate) const BPF_DW: u8 = 0x18;
pub(crate) const BPF_IMM: u8 = 0x00;
pub(crate) const BPF_MEM: u8 = 0x60;
pub(crate) const BPF_K: u8 = 0x00;
pub(crate) const BPF_MOV: u8 = 0xb0;
pub(crate) const BPF_CALL: u8 = 0x80;
pub(crate) const BPF_EXIT: u8 = 0x90;

/// `src_reg` of `ld_imm64` meaning "imm is a map fd" (`bpf.h`).
pub(crate) const BPF_PSEUDO_MAP_FD: u8 = 1;
/// `BPF_FUNC_redirect_map` helper id (`bpf.h` `___BPF_FUNC_MAPPER`).
pub(crate) const BPF_FUNC_REDIRECT_MAP: i32 = 51;
/// `offsetof(struct xdp_md, rx_queue_index)`.
pub(crate) const XDP_MD_RX_QUEUE_INDEX: i16 = 16;
/// `enum xdp_action` `XDP_PASS`.
pub(crate) const XDP_PASS: i32 = 2;
/// `enum xdp_action` `XDP_DROP`, recorded for the fallback decision only.
#[cfg(test)]
pub(crate) const XDP_DROP: i32 = 1;

/// Action `bpf_redirect_map` returns when the XSKMAP slot of the receive
/// queue is empty (the low two flag bits, Linux 5.3+).
///
/// `XDP_PASS` is chosen deliberately: a queue without a bound socket keeps
/// ordinary kernel-stack delivery, exactly as if no program were attached,
/// so a misconfigured RSS spread or a socket that is not yet (or no longer)
/// in the map cannot silently black-hole traffic. The trade-off is that
/// such packets reach the host stack instead of the router: M2 binds one
/// queue per port, and operators must steer traffic to that queue
/// (single-queue device or ethtool RSS/ntuple). See XDP-050.
pub(crate) const REDIRECT_FALLBACK_ACTION: i32 = XDP_PASS;

const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;

/// Index of the `ld_imm64` low slot whose `imm` carries the XSKMAP fd.
pub(crate) const MAP_FD_SLOT: usize = 1;

/// Number of `struct bpf_insn` slots (the `ld_imm64` uses two).
pub(crate) const REDIRECT_PROGRAM_LEN: usize = 6;

/// Program template with map fd 0; [`redirect_program`] patches the fd.
pub(crate) const REDIRECT_PROGRAM_TEMPLATE: [BpfInsn; REDIRECT_PROGRAM_LEN] = [
    // 0x61: LDX | MEM | W. dst r2, src r1, off 16.
    BpfInsn::new(BPF_LDX | BPF_MEM | BPF_W, R2, R1, XDP_MD_RX_QUEUE_INDEX, 0),
    // 0x18: LD | IMM | DW, low half. dst r1, src PSEUDO_MAP_FD, imm = fd.
    BpfInsn::new(BPF_LD | BPF_IMM | BPF_DW, R1, BPF_PSEUDO_MAP_FD, 0, 0),
    // ld_imm64 high half: all-zero code/regs/off, imm = upper 32 bits (0).
    BpfInsn::new(0, 0, 0, 0, 0),
    // 0xb7: ALU64 | MOV | K. dst r3, imm XDP_PASS.
    BpfInsn::new(
        BPF_ALU64 | BPF_MOV | BPF_K,
        R3,
        0,
        0,
        REDIRECT_FALLBACK_ACTION,
    ),
    // 0x85: JMP | CALL. imm = helper id.
    BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP),
    // 0x95: JMP | EXIT.
    BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
];

/// Returns the program with `map_fd` in the `ld_imm64` slot.
pub(crate) const fn redirect_program(map_fd: i32) -> [BpfInsn; REDIRECT_PROGRAM_LEN] {
    let mut program = REDIRECT_PROGRAM_TEMPLATE;
    program[MAP_FD_SLOT].imm = map_fd;
    program
}

/// License string passed to `BPF_PROG_LOAD`.
///
/// It is the repository's SPDX expression. Linux v6.8 copies at most 127
/// bytes and sets `gpl_compatible` from `license_is_gpl_compatible`; that
/// bit only gates helpers declared `.gpl_only = true` (and kfuncs). The one
/// helper called here, `bpf_xdp_redirect_map_proto` in `net/core/filter.c`,
/// is `.gpl_only = false`, so the kernel accepts this non-GPL string. See
/// XDP-049.
pub(crate) const PROGRAM_LICENSE: &CStr = c"MIT OR Apache-2.0";

/// `BPF_OBJ_NAME_LEN` (`bpf.h`): name bytes plus the NUL.
pub(crate) const BPF_OBJ_NAME_LEN: usize = 16;

const fn object_name(name: &[u8]) -> [u8; BPF_OBJ_NAME_LEN] {
    assert!(name.len() < BPF_OBJ_NAME_LEN);
    let mut bytes = [0_u8; BPF_OBJ_NAME_LEN];
    let mut index = 0;
    while index < name.len() {
        // Linux `bpf_obj_name_cpy` accepts only alphanumerics, `_`, `.`.
        assert!(name[index].is_ascii_alphanumeric() || name[index] == b'_');
        bytes[index] = name[index];
        index += 1;
    }
    bytes
}

/// Program name visible to `bpftool prog`.
pub(crate) const PROGRAM_NAME: [u8; BPF_OBJ_NAME_LEN] = object_name(b"ruster_xsk");
/// XSKMAP name visible to `bpftool map`.
pub(crate) const MAP_NAME: [u8; BPF_OBJ_NAME_LEN] = object_name(b"ruster_xsks");

/// `XDP_FLAGS_SKB_MODE` (`if_link.h`): generic (skb) XDP.
pub(crate) const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
/// `XDP_FLAGS_DRV_MODE` (`if_link.h`): native (driver) XDP.
pub(crate) const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden encoding, written out independently of the constructors.
    const GOLDEN: [[u8; 8]; REDIRECT_PROGRAM_LEN] = [
        [0x61, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x18, 0x11, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0xb7, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00],
        [0x85, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00],
        [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    #[test]
    fn xdp_redirect_program_encoding_is_golden() {
        let program = redirect_program(42);
        for (insn, golden) in program.iter().zip(GOLDEN) {
            assert_eq!(insn.to_le_bytes(), golden);
        }
        // The template differs only in the map fd slot.
        for (index, (template, patched)) in
            REDIRECT_PROGRAM_TEMPLATE.iter().zip(program).enumerate()
        {
            if index == MAP_FD_SLOT {
                assert_eq!((template.imm, patched.imm), (0, 42));
            } else {
                assert_eq!(*template, patched);
            }
        }
        // Negative fds are never loaded, but encoding stays two's complement.
        assert_eq!(
            redirect_program(-1)[MAP_FD_SLOT].to_le_bytes()[4..],
            [0xff; 4]
        );
    }

    #[test]
    fn xdp_program_constants_match_linux_uapi() {
        assert_eq!(
            (BPF_LD, BPF_LDX, BPF_JMP, BPF_ALU64),
            (0x00, 0x01, 0x05, 0x07)
        );
        assert_eq!((BPF_W, BPF_DW, BPF_IMM, BPF_MEM), (0x00, 0x18, 0x00, 0x60));
        assert_eq!(
            (BPF_K, BPF_MOV, BPF_CALL, BPF_EXIT),
            (0x00, 0xb0, 0x80, 0x90)
        );
        assert_eq!(
            (
                BPF_PSEUDO_MAP_FD,
                BPF_FUNC_REDIRECT_MAP,
                XDP_MD_RX_QUEUE_INDEX
            ),
            (1, 51, 16)
        );
        assert_eq!((XDP_DROP, XDP_PASS, REDIRECT_FALLBACK_ACTION), (1, 2, 2));
        assert_eq!((XDP_FLAGS_SKB_MODE, XDP_FLAGS_DRV_MODE), (2, 4));
        assert_eq!(PROGRAM_LICENSE.to_bytes(), b"MIT OR Apache-2.0");
        assert!(PROGRAM_LICENSE.to_bytes_with_nul().len() <= 128);
        assert_eq!(&PROGRAM_NAME[..11], b"ruster_xsk\0");
        assert_eq!(&MAP_NAME[..12], b"ruster_xsks\0");
        assert_eq!(PROGRAM_NAME[BPF_OBJ_NAME_LEN - 1], 0);
    }
}

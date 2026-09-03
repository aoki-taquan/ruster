//! Pure-Rust encoding and loading of the minimum XDP-to-XSKMAP program.
//!
//! The instruction encoder is intentionally independent of the native syscall
//! seam. It can therefore be checked at the byte level without a NIC or a
//! kernel. Loading remains a cold operation and owns the returned program fd
//! through [`XdpRedirectProgram`]. The loaded program can be attached to a
//! link through the sibling rtnetlink transaction, whose returned owner also
//! detaches the program during teardown.

use crate::{
    abi::{
        BPF_ALU64, BPF_CALL, BPF_DW, BPF_EXIT, BPF_FUNC_REDIRECT_MAP, BPF_IMM, BPF_JMP, BPF_K,
        BPF_LD, BPF_LDX, BPF_MEM, BPF_MOV, BPF_PSEUDO_MAP_FD, BPF_REG_1, BPF_REG_2, BPF_REG_3,
        BPF_W, BPF_X, XDP_MD_RX_QUEUE_INDEX_OFFSET, XDP_PASS,
    },
    netlink::{ValidatedXdpAttachFlags, XdpAttachMode, XdpAttachOptions, XdpAttachment},
    XdpAttachError, XdpProgramError, XskMap,
};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::netlink::attach_program;

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
use crate::{ensure_native_syscall_supported, NativeSyscallPlatformError};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
use crate::native_unsafe::syscall::{
    BpfProgramArgumentError, BpfProgramResourceError, LinuxSyscalls, OwnedBpfProgram,
};

/// The minimum program contains one context load, a two-slot map-fd load,
/// two argument moves, one helper call, and one exit.
pub const XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT: usize = 7;
/// Each Linux `struct bpf_insn` is eight bytes on the reviewed x86_64 ABI.
pub const XDP_REDIRECT_PROGRAM_BYTECODE_LEN: usize = XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT * 8;

const _: [(); 8] = [(); std::mem::size_of::<BpfInsn>()];
const _: [(); 4] = [(); std::mem::align_of::<BpfInsn>()];

/// One Linux `struct bpf_insn`.
///
/// Linux declares `code` at byte 0, the four-bit `dst_reg` and `src_reg`
/// bitfields together at byte 1, signed `off` at bytes 2..4, and signed `imm`
/// at bytes 4..8 (`bpf.h:72-78`). `dst_src` stores those two nibbles exactly:
/// the destination occupies bits 0..3 and the source occupies bits 4..7.
/// Consequently this C-layout Rust representation is exactly eight bytes and
/// does not rely on Rust bit-field layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfInsn {
    /// Linux eBPF opcode byte.
    pub code: u8,
    /// Packed register byte: destination low nibble, source high nibble.
    pub dst_src: u8,
    /// Signed 16-bit instruction offset.
    pub off: i16,
    /// Signed 32-bit immediate.
    pub imm: i32,
}

impl BpfInsn {
    /// Creates one instruction with the Linux register-nibble packing.
    ///
    /// Register numbers are four-bit values as defined by `bpf.h:53-67`.
    /// Callers of this low-level constructor should pass values in `0..=15`;
    /// the reviewed program uses only registers 1, 2, and 3.
    #[must_use]
    pub const fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_src: (dst_reg & 0x0f) | ((src_reg & 0x0f) << 4),
            off,
            imm,
        }
    }

    /// Returns the destination register nibble.
    #[must_use]
    pub const fn dst_reg(self) -> u8 {
        self.dst_src & 0x0f
    }

    /// Returns the source register nibble.
    #[must_use]
    pub const fn src_reg(self) -> u8 {
        self.dst_src >> 4
    }

    /// Serializes the C-layout instruction in the reviewed little-endian
    /// x86_64 byte order.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code,
            self.dst_src,
            off[0],
            off[1],
            imm[0],
            imm[1],
            imm[2],
            imm[3],
        ]
    }
}

/// Builds the seven instructions for an XDP program that redirects by RX
/// queue id into `map_fd`.
///
/// The first instruction reads `ctx->rx_queue_index` while `r1` still holds
/// the XDP context. Only after that read does the two-instruction
/// `BPF_LD_MAP_FD` pseudo-instruction overwrite `r1` with the XSKMAP pointer.
/// This ordering is required by the verifier and preserves the context until
/// its only access is complete.
#[must_use]
pub const fn xdp_redirect_instructions(
    map_fd: u32,
) -> [BpfInsn; XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT] {
    [
        // BPF_LDX | BPF_MEM | BPF_W, r3 = *(u32 *)(r1 + 16).
        BpfInsn::new(
            BPF_LDX | BPF_MEM | BPF_W,
            BPF_REG_3,
            BPF_REG_1,
            XDP_MD_RX_QUEUE_INDEX_OFFSET,
            0,
        ),
        // BPF_LD | BPF_DW | BPF_IMM with BPF_PSEUDO_MAP_FD in src_reg.
        BpfInsn::new(
            BPF_LD | BPF_DW | BPF_IMM,
            BPF_REG_1,
            BPF_PSEUDO_MAP_FD,
            0,
            map_fd as i32,
        ),
        // The second half of BPF_LD_MAP_FD carries the high 32 bits.
        BpfInsn::new(0, 0, 0, 0, 0),
        // BPF_ALU64 | BPF_MOV | BPF_X, r2 = r3 (the map key).
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_3, 0, 0),
        // BPF_ALU64 | BPF_MOV | BPF_K, r3 = XDP_PASS (fallback flags).
        BpfInsn::new(
            BPF_ALU64 | BPF_MOV | BPF_K,
            BPF_REG_3,
            0,
            0,
            XDP_PASS as i32,
        ),
        // BPF_JMP | BPF_CALL, call bpf_redirect_map (helper id 51).
        BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP),
        // BPF_JMP | BPF_EXIT.
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    ]
}

/// Encodes [`xdp_redirect_instructions`] as the byte extent passed to
/// `BPF_PROG_LOAD`.
#[must_use]
pub fn encode_xdp_redirect_program(map_fd: u32) -> [u8; XDP_REDIRECT_PROGRAM_BYTECODE_LEN] {
    let instructions = xdp_redirect_instructions(map_fd);
    let mut bytes = [0_u8; XDP_REDIRECT_PROGRAM_BYTECODE_LEN];
    let mut index = 0;
    while index < XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT {
        let encoded = instructions[index].to_bytes();
        let start = index * 8;
        let end = start + 8;
        bytes[start..end].copy_from_slice(&encoded);
        index += 1;
    }
    bytes
}

/// Alias emphasizing that this is a fixed-size bytecode artifact.
#[must_use]
pub fn xdp_redirect_program_bytecode(map_fd: u32) -> [u8; XDP_REDIRECT_PROGRAM_BYTECODE_LEN] {
    encode_xdp_redirect_program(map_fd)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
static PROGRAM_SYSCALLS: LinuxSyscalls = LinuxSyscalls;

/// An owned, loaded XDP redirect program.
///
/// `load` accepts an [`XskMap`] so the map relationship is explicit at the
/// public boundary. The program fd is closed exactly once by [`Self::close`]
/// or `Drop`. [`Self::attach`] performs the cold rtnetlink operation and
/// returns an [`XdpAttachment`] whose teardown detaches the program.
pub struct XdpRedirectProgram {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    inner: OwnedBpfProgram<'static, LinuxSyscalls>,
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    _unsupported: (),
}

impl XdpRedirectProgram {
    /// Loads the minimum redirect program using `map` as its XSKMAP target.
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub fn load(map: &XskMap) -> Result<Self, XdpProgramError> {
        let map_fd = map.raw_fd();
        let map_fd = u32::try_from(map_fd)
            .map_err(|_| XdpProgramError::InvalidMapFileDescriptor { fd: map_fd })?;
        let bytecode = encode_xdp_redirect_program(map_fd);
        let inner = OwnedBpfProgram::load(
            &PROGRAM_SYSCALLS,
            &bytecode,
            XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT as u32,
        )
        .map_err(map_program_error)?;
        Ok(Self { inner })
    }

    /// Returns the fixed instruction count submitted by [`Self::load`].
    #[must_use]
    pub const fn instruction_count() -> usize {
        XDP_REDIRECT_PROGRAM_INSTRUCTION_COUNT
    }

    /// Returns the fixed bytecode length submitted by [`Self::load`].
    #[must_use]
    pub const fn bytecode_len() -> usize {
        XDP_REDIRECT_PROGRAM_BYTECODE_LEN
    }

    /// Explicitly closes the program descriptor and reports close failures.
    pub fn close(self) -> Result<(), XdpProgramError> {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        {
            self.inner.close().map_err(map_program_error)
        }
        #[cfg(not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )))]
        {
            let _ = self;
            Ok(())
        }
    }

    /// Attaches this program to `ifindex` using the safe default policy.
    ///
    /// The default is SKB mode plus `XDP_FLAGS_UPDATE_IF_NOEXIST`: SKB mode is
    /// usable by veth, while DRV mode depends on a particular NIC driver, and
    /// an existing program must never be replaced implicitly.
    pub fn attach(&self, ifindex: u32) -> Result<XdpAttachment, XdpAttachError> {
        self.attach_with_flags(ifindex, ValidatedXdpAttachFlags::default())
    }

    /// Attaches this program in explicitly selected SKB or DRV mode.
    pub fn attach_with_mode(
        &self,
        ifindex: u32,
        mode: XdpAttachMode,
    ) -> Result<XdpAttachment, XdpAttachError> {
        self.attach_with_flags(ifindex, ValidatedXdpAttachFlags::for_mode(mode))
    }

    /// Attaches this program with raw Linux flags after applying the checked
    /// no-replace/SKB-or-DRV policy.
    pub fn attach_with_raw_flags(
        &self,
        ifindex: u32,
        raw_flags: u32,
    ) -> Result<XdpAttachment, XdpAttachError> {
        let flags =
            ValidatedXdpAttachFlags::new(raw_flags).map_err(XdpAttachError::Configuration)?;
        self.attach_with_flags(ifindex, flags)
    }

    /// Alias for [`Self::attach_with_flags`] using the option-oriented public
    /// name.
    pub fn attach_with_options(
        &self,
        ifindex: u32,
        options: XdpAttachOptions,
    ) -> Result<XdpAttachment, XdpAttachError> {
        self.attach_with_flags(ifindex, options)
    }

    /// Attaches this program with a previously validated no-replace flag word.
    pub fn attach_with_flags(
        &self,
        ifindex: u32,
        flags: ValidatedXdpAttachFlags,
    ) -> Result<XdpAttachment, XdpAttachError> {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        {
            attach_program(self.raw_fd(), ifindex, flags)
        }
        #[cfg(not(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        )))]
        {
            let _ = (self, ifindex, flags);
            Err(XdpAttachError::Platform(unsupported_platform_error()))
        }
    }

    /// Returns the owned program fd to the in-crate future attach layer.
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(crate) fn raw_fd(&self) -> i32 {
        self.inner.raw()
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
impl XdpRedirectProgram {
    /// Returns a typed unsupported-platform error without entering a syscall.
    pub fn load(_map: &XskMap) -> Result<Self, XdpProgramError> {
        Err(XdpProgramError::Platform(unsupported_platform_error()))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn map_program_error(error: BpfProgramResourceError) -> XdpProgramError {
    match error {
        BpfProgramResourceError::Platform(error) => XdpProgramError::Platform(error),
        BpfProgramResourceError::Argument(error) => match error {
            BpfProgramArgumentError::InstructionCountMismatch { insn_cnt, byte_len } => {
                XdpProgramError::InstructionCountMismatch { insn_cnt, byte_len }
            }
            BpfProgramArgumentError::InvalidLogSize => {
                unreachable!("the fixed verifier buffer fits u32")
            }
        },
        BpfProgramResourceError::Syscall {
            operation,
            errno,
            verifier_log,
        } => {
            if errno.raw() == Some(1) {
                XdpProgramError::PermissionDenied {
                    operation,
                    verifier_log,
                }
            } else {
                XdpProgramError::Syscall {
                    operation,
                    errno: errno.raw(),
                    verifier_log,
                }
            }
        }
        BpfProgramResourceError::InvalidFileDescriptor {
            operation,
            verifier_log,
        } => XdpProgramError::InvalidFileDescriptor {
            operation,
            verifier_log,
        },
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn unsupported_platform_error() -> NativeSyscallPlatformError {
    match ensure_native_syscall_supported() {
        Ok(()) => unreachable!("unsupported XDP program path on a supported target"),
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::XdpProgramOperation;

    #[test]
    fn bpf_insn_layout_packs_register_nibbles_and_little_endian_fields() {
        assert_eq!(std::mem::size_of::<BpfInsn>(), 8);
        assert_eq!(std::mem::align_of::<BpfInsn>(), 4);
        let instruction = BpfInsn::new(0xa5, 0x03, 0x0e, -2, 0x1122_3344);
        assert_eq!(instruction.dst_reg(), 3);
        assert_eq!(instruction.src_reg(), 0x0e);
        assert_eq!(instruction.dst_src, 0xe3);
        assert_eq!(
            instruction.to_bytes(),
            [0xa5, 0xe3, 0xfe, 0xff, 0x44, 0x33, 0x22, 0x11]
        );
    }

    #[test]
    fn redirect_program_is_fixed_seven_instructions_and_exact_bytes() {
        let instructions = xdp_redirect_instructions(42);
        assert_eq!(instructions.len(), 7);
        assert_eq!(XdpRedirectProgram::instruction_count(), 7);
        assert_eq!(XdpRedirectProgram::bytecode_len(), 56);
        assert_eq!(
            encode_xdp_redirect_program(42),
            [
                0x61, 0x13, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // r3 = *(u32 *)(r1 + 16)
                0x18, 0x11, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // map fd low half
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // map fd high half
                0xbf, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = r3
                0xb7, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // r3 = XDP_PASS
                0x85, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, // call 51
                0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
            ]
        );
    }

    #[test]
    fn map_fd_pseudo_instruction_occupies_two_slots() {
        let instructions = xdp_redirect_instructions(0x1122_3344);
        assert_eq!(instructions[1].src_reg(), BPF_PSEUDO_MAP_FD);
        assert_eq!(instructions[1].dst_reg(), BPF_REG_1);
        assert_eq!(instructions[1].imm, 0x1122_3344_i32);
        assert_eq!(instructions[2], BpfInsn::new(0, 0, 0, 0, 0));
        assert_eq!(instructions.len() * 8, 16 + 5 * 8);
    }

    #[test]
    fn context_read_precedes_r1_map_overwrite() {
        let instructions = xdp_redirect_instructions(42);
        assert_eq!(instructions[0].dst_reg(), BPF_REG_3);
        assert_eq!(instructions[0].src_reg(), BPF_REG_1);
        assert_eq!(instructions[0].off, XDP_MD_RX_QUEUE_INDEX_OFFSET);
        assert_eq!(instructions[1].dst_reg(), BPF_REG_1);
        assert_eq!(instructions[3].dst_reg(), BPF_REG_2);
        assert_eq!(instructions[3].src_reg(), BPF_REG_3);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    #[test]
    fn program_load_eperm_is_typed_and_keeps_verifier_log() {
        let error = map_program_error(BpfProgramResourceError::Syscall {
            operation: XdpProgramOperation::Load,
            errno: crate::native_unsafe::syscall::Errno::Linux(1),
            verifier_log: "permission boundary".to_owned(),
        });
        assert!(error.is_permission_denied());
        assert_eq!(error.verifier_log(), Some("permission boundary"));
        assert!(error.to_string().contains("CAP_BPF"));
        assert!(error.to_string().contains("permission boundary"));
    }
}

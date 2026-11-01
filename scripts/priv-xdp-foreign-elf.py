#!/usr/bin/env python3
"""Writes a minimal relocatable eBPF ELF object holding one `XDP_PASS` program.

The privileged smoke (`scripts/priv-xdp-smoke.sh`) loads it with
`ip link set dev <veth> xdpgeneric obj <file> sec xdp` as a *foreign*,
netlink-attached program inside its dedicated network namespace, then checks
that ruster refuses to attach over it and leaves it untouched. No compiler is
needed: the object is assembled byte by byte here.

Program (section `xdp`, symbol `xdp_pass`):
    b7 00 00 00 02 00 00 00    r0 = 2 (XDP_PASS)
    95 00 00 00 00 00 00 00    exit
"""

import struct
import sys

EM_BPF = 247
ET_REL = 1
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_FUNC = 2

PROGRAM = bytes.fromhex("b700000002000000" "9500000000000000")
LICENSE = b"MIT OR Apache-2.0\0"
STRTAB = b"\0xdp_pass\0"
SHSTRTAB = b"\0xdp\0license\0.symtab\0.strtab\0.shstrtab\0"


def name(table, text):
    return table.index(text.encode() + b"\0")


def symbol(st_name, info, shndx, value, size):
    return struct.pack("<IBBHQQ", st_name, info, 0, shndx, value, size)


SYMTAB = symbol(0, 0, 0, 0, 0) + symbol(
    name(STRTAB, "xdp_pass"), (STB_GLOBAL << 4) | STT_FUNC, 1, 0, len(PROGRAM)
)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: priv-xdp-foreign-elf.py OUTPUT")
    # (name, type, flags, data, link, info, align, entsize)
    sections = [
        ("xdp", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, PROGRAM, 0, 0, 8, 0),
        ("license", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, LICENSE, 0, 0, 1, 0),
        (".symtab", SHT_SYMTAB, 0, SYMTAB, 4, 1, 8, 24),
        (".strtab", SHT_STRTAB, 0, STRTAB, 0, 0, 1, 0),
        (".shstrtab", SHT_STRTAB, 0, SHSTRTAB, 0, 0, 1, 0),
    ]
    body = b""
    offset = 64
    headers = [b"\0" * 64]
    for sh_name, sh_type, flags, data, link, info, align, entsize in sections:
        padding = (-offset) % 8
        body += b"\0" * padding
        offset += padding
        headers.append(
            struct.pack(
                "<IIQQQQIIQQ",
                name(SHSTRTAB, sh_name),
                sh_type,
                flags,
                0,
                offset,
                len(data),
                link,
                info,
                align,
                entsize,
            )
        )
        body += data
        offset += len(data)
    padding = (-offset) % 8
    body += b"\0" * padding
    shoff = offset + padding
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_REL,
        EM_BPF,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        len(headers),
        len(headers) - 1,
    )
    with open(sys.argv[1], "wb") as output:
        output.write(header + body + b"".join(headers))


if __name__ == "__main__":
    main()

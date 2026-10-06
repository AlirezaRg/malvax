"""Builds minimal, non-executable ELF64 test fixtures byte-by-byte.

The fixtures are never run. They exist so the parser can be tested without
shipping or compiling real binaries.
"""

from __future__ import annotations

import struct

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_DYNAMIC = 6
DT_NULL, DT_NEEDED, DT_STRTAB, DT_FLAGS = 0, 1, 5, 30
DF_BIND_NOW = 0x8


def _strtab(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = b"\x00"
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(blob)
        blob += name.encode() + b"\x00"
    return blob, offsets


def build_elf64(
    *,
    e_type: int = 3,  # ET_DYN
    interp: str | None = "/lib64/ld-linux-x86-64.so.2",
    nx_stack: bool = True,
    relro: bool = True,
    bind_now: bool = False,
    needed: list[str] | None = None,
    imports: list[str] | None = None,
) -> bytes:
    needed = needed or []
    imports = imports or []
    dynstr, off = _strtab(needed + imports)
    # Symbol table: null symbol, then one undefined global function per import.
    dynsym = b"\x00" * 24
    for name in imports:
        dynsym += struct.pack("<IBBHQQ", off[name], 0x12, 0, 0, 0, 0)  # GLOBAL FUNC, UNDEF
    dyn_entries = [(DT_STRTAB, 0)]
    dyn_entries += [(DT_NEEDED, off[name]) for name in needed]
    if bind_now:
        dyn_entries.append((DT_FLAGS, DF_BIND_NOW))
    dyn_entries.append((DT_NULL, 0))
    dynamic = b"".join(struct.pack("<qQ", t, v) for t, v in dyn_entries)
    interp_bytes = (interp.encode() + b"\x00") if interp else b""
    shstr, shoff = _strtab([".dynstr", ".dynsym", ".dynamic", ".shstrtab"])

    # Layout: header(64) | phdrs | interp | dynstr | dynsym | dynamic | shstrtab | shdrs
    phdr_count = 2 + (1 if interp else 0) + (1 if relro else 0)
    phdrs_size = 56 * phdr_count
    cursor = 64 + phdrs_size
    interp_off = cursor
    cursor += len(interp_bytes)
    dynstr_off = cursor
    cursor += len(dynstr)
    dynsym_off = cursor
    cursor += len(dynsym)
    dynamic_off = cursor
    cursor += len(dynamic)
    shstr_off = cursor
    cursor += len(shstr)
    shdr_off = (cursor + 7) & ~7

    phdrs = b""
    if interp:
        phdrs += _phdr(PT_INTERP, 4, interp_off, len(interp_bytes))
    phdrs += _phdr(PT_DYNAMIC, 6, dynamic_off, len(dynamic))
    phdrs += _phdr(PT_GNU_STACK, 6 if nx_stack else 7, 0, 0)
    if relro:
        phdrs += _phdr(PT_GNU_RELRO, 4, dynamic_off, len(dynamic))

    # Section headers: null, .dynstr, .dynsym, .dynamic, .shstrtab
    shdrs = b"\x00" * 64
    shdrs += _shdr(shstr, ".dynstr", 3, dynstr_off, len(dynstr), 0)
    shdrs += _shdr(shstr, ".dynsym", SHT_DYNSYM, dynsym_off, len(dynsym), 1)
    shdrs += _shdr(shstr, ".dynamic", SHT_DYNAMIC, dynamic_off, len(dynamic), 1)
    shdrs += _shdr(shstr, ".shstrtab", SHT_STRTAB, shstr_off, len(shstr), 0)

    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, 62, 1, 0x1000, 64, shdr_off, 0, 64, 56, phdr_count, 64, 5, 4,
    )
    body = bytearray(header + phdrs)
    for blob, at in (
        (interp_bytes, interp_off),
        (dynstr, dynstr_off),
        (dynsym, dynsym_off),
        (dynamic, dynamic_off),
        (shstr, shstr_off),
    ):
        body += b"\x00" * (at - len(body)) + blob
    body += b"\x00" * (shdr_off - len(body)) + shdrs
    return bytes(body)


def _phdr(p_type: int, flags: int, offset: int, size: int) -> bytes:
    return struct.pack("<IIQQQQQQ", p_type, flags, offset, offset, offset, size, size, 8)


def _shdr(shstr: bytes, name: str, sh_type: int, offset: int, size: int, link: int) -> bytes:
    name_off = _strtab_offset(shstr, name)
    entsize = 24 if sh_type in (SHT_DYNSYM, SHT_DYNAMIC) else 0
    return struct.pack("<IIQQQQIIQQ", name_off, sh_type, 0, 0, offset, size, link, 0, 8, entsize)


def _strtab_offset(table: bytes, name: str) -> int:
    return table.index(name.encode() + b"\x00")

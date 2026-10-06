"""Static ELF analysis (Phase 2).

Parses ELF headers, program headers, section headers, the dynamic section, the interpreter,
dynamic symbols and security mitigations. Pure stdlib: the file is read, never executed,
and no external parser (readelf, objdump) is invoked.

Missing information is reported as None, never as a vulnerability.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"
PT_INTERP = 3
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1
DT_NEEDED = 1
DT_RUNPATH = 29
DT_RPATH = 15
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_NULL = 0
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
STACK_CHK_SYMBOL = "__stack_chk_fail"
ET_DYN = 3
ET_EXEC = 2
SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHT_DYNAMIC = 6

_ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_MACHINES = {3: "x86", 8: "MIPS", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


class ElfParseError(ValueError):
    """Raised when the input is not a well-formed ELF file."""


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    type: int
    flags: int
    address: int
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class Segment:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass(frozen=True, slots=True)
class Mitigations:
    pie: bool | None
    nx: bool | None
    relro: str | None  # "full", "partial", "none", or None if undetermined
    stack_canary: bool | None


@dataclass(slots=True)
class ElfReport:
    elf_class: str
    endianness: str
    os_abi: int
    elf_type: str
    machine: str
    entry_point: int
    sections: list[Section] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    needed_libraries: list[str] = field(default_factory=list)
    runpath: str | None = None
    interpreter: str | None = None
    imported_symbols: list[str] = field(default_factory=list)
    exported_symbols: list[str] = field(default_factory=list)
    mitigations: Mitigations = field(
        default_factory=lambda: Mitigations(None, None, None, None)
    )


class _Reader:
    """Bounds-checked accessor. Every read is validated against the file size."""

    def __init__(self, data: bytes, endian: str) -> None:
        self.data = data
        self.endian = endian

    def unpack(self, fmt: str, offset: int) -> tuple[int, ...]:
        size = struct.calcsize(self.endian + fmt)
        if offset < 0 or offset + size > len(self.data):
            raise ElfParseError(f"read of {size} bytes at {offset} is out of bounds")
        return struct.unpack_from(self.endian + fmt, self.data, offset)

    def cstring(self, offset: int, limit: int = 4096) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\x00", offset, min(len(self.data), offset + limit))
        if end == -1:
            end = min(len(self.data), offset + limit)
        return self.data[offset:end].decode("utf-8", errors="replace")

    def slice(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ElfParseError(f"slice {offset}+{size} exceeds file size")
        return self.data[offset : offset + size]


def parse_elf_bytes(data: bytes) -> ElfReport:
    if len(data) < 16 or not data.startswith(ELF_MAGIC):
        raise ElfParseError("not an ELF file")
    ei_class, ei_data, _version, os_abi = data[4], data[5], data[6], data[7]
    if ei_class not in (1, 2):
        raise ElfParseError(f"unknown ELF class {ei_class}")
    if ei_data not in (1, 2):
        raise ElfParseError(f"unknown endianness {ei_data}")
    endian = "<" if ei_data == 1 else ">"
    rd = _Reader(data, endian)
    is64 = ei_class == 2

    if is64:
        (e_type, e_machine, _ver, entry, phoff, shoff, _flags, _ehsize, phentsize, phnum,
         shentsize, shnum, shstrndx) = rd.unpack("HHIQQQIHHHHHH", 16)
        ph_fmt, sh_fmt, sym_fmt, dyn_fmt = "IIQQQQQQ", "IIQQQQIIQQ", "IBBHQQ", "qQ"
    else:
        (e_type, e_machine, _ver, entry, phoff, shoff, _flags, _ehsize, phentsize, phnum,
         shentsize, shnum, shstrndx) = rd.unpack("HHIIIIIHHHHHH", 16)
        ph_fmt, sh_fmt, sym_fmt, dyn_fmt = "IIIIIIII", "IIIIIIIIII", "IIIBBH", "iI"

    report = ElfReport(
        elf_class="ELF64" if is64 else "ELF32",
        endianness="little" if ei_data == 1 else "big",
        os_abi=os_abi,
        elf_type=_ELF_TYPES.get(e_type, f"UNKNOWN({e_type})"),
        machine=_MACHINES.get(e_machine, f"UNKNOWN({e_machine})"),
        entry_point=entry,
    )

    segments = _read_segments(rd, is64, phoff, phentsize, phnum, ph_fmt)
    report.segments = segments
    report.interpreter = _read_interpreter(rd, segments)

    table = _read_sections(rd, is64, shoff, shentsize, shnum, shstrndx, sh_fmt)
    report.sections = [s.section for s in table]

    dyn_entries: list[tuple[int, int]] = []
    dynamic = next((s for s in table if s.section.type == SHT_DYNAMIC), None)
    if dynamic is not None:
        dyn_entries = _read_dynamic(rd, dynamic.section, dyn_fmt)
        strtab = table[dynamic.link].section if dynamic.link < len(table) else None
        if strtab is not None:
            _apply_dynamic(report, rd, dyn_entries, strtab.offset)

    dynsym = next((s for s in table if s.section.type == SHT_DYNSYM), None)
    if dynsym is not None and dynsym.link < len(table):
        imports, exports = _read_symbols(
            rd, dynsym.section, table[dynsym.link].section.offset, sym_fmt, is64
        )
        report.imported_symbols = imports
        report.exported_symbols = exports

    report.mitigations = _mitigations(report, dyn_entries)
    return report


def analyze_elf(path: Path) -> ElfReport:
    return parse_elf_bytes(path.read_bytes())


def _read_segments(rd: _Reader, is64: bool, phoff: int, entsize: int, num: int,
                   fmt: str) -> list[Segment]:
    out: list[Segment] = []
    for i in range(num):
        base = phoff + i * entsize
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, _al = rd.unpack(fmt, base)
        else:
            p_type, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_flags, _al = rd.unpack(fmt, base)
        out.append(Segment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    return out


def _read_interpreter(rd: _Reader, segments: list[Segment]) -> str | None:
    for seg in segments:
        if seg.type == PT_INTERP:
            raw = rd.slice(seg.offset, seg.filesz).split(b"\x00", 1)[0]
            return raw.decode("utf-8", errors="replace")
    return None


@dataclass(frozen=True, slots=True)
class _TableEntry:
    section: Section
    link: int


def _read_sections(rd: _Reader, is64: bool, shoff: int, entsize: int, num: int,
                   shstrndx: int, fmt: str) -> list[_TableEntry]:
    if shoff == 0 or num == 0:
        return []
    raw = []
    for i in range(num):
        base = shoff + i * entsize
        name, typ, flags, addr, off, size, link, _info, _al, _es = rd.unpack(fmt, base)
        raw.append((name, typ, flags, addr, off, size, link))
    names_off = raw[shstrndx][4] if shstrndx < len(raw) else 0
    table: list[_TableEntry] = []
    for name, typ, flags, addr, off, size, link in raw:
        sec_name = rd.cstring(names_off + name) if names_off else ""
        table.append(_TableEntry(Section(sec_name, typ, flags, addr, off, size), link))
    return table


def _read_dynamic(rd: _Reader, section: Section, fmt: str) -> list[tuple[int, int]]:
    entries: list[tuple[int, int]] = []
    entsize = struct.calcsize(rd.endian + fmt)
    for pos in range(section.offset, section.offset + section.size - entsize + 1, entsize):
        tag, val = rd.unpack(fmt, pos)
        if tag == DT_NULL:
            break
        entries.append((tag, val))
    return entries


def _apply_dynamic(report: ElfReport, rd: _Reader, entries: list[tuple[int, int]],
                   strtab_offset: int) -> None:
    for tag, val in entries:
        if tag == DT_NEEDED:
            report.needed_libraries.append(rd.cstring(strtab_offset + val))
        elif tag in (DT_RUNPATH, DT_RPATH):
            report.runpath = rd.cstring(strtab_offset + val)


def _read_symbols(rd: _Reader, dynsym: Section, str_offset: int, fmt: str,
                  is64: bool) -> tuple[list[str], list[str]]:
    imports: list[str] = []
    exports: list[str] = []
    entsize = struct.calcsize(rd.endian + fmt)
    for pos in range(dynsym.offset + entsize, dynsym.offset + dynsym.size, entsize):
        if is64:
            st_name, _info, _other, st_shndx, _value, _sz = rd.unpack(fmt, pos)
        else:
            st_name, _value, _sz, _info, _other, st_shndx = rd.unpack(fmt, pos)
        name = rd.cstring(str_offset + st_name)
        if not name:
            continue
        (imports if st_shndx == 0 else exports).append(name)
    return imports, exports


def _mitigations(report: ElfReport, dyn_entries: list[tuple[int, int]]) -> Mitigations:
    # PIE is claimed only for ET_DYN with an interpreter (a runnable position-independent
    # executable). ET_EXEC is definitively not PIE. A shared object (ET_DYN, no interpreter)
    # is left as None: it is not an executable, so the question does not apply.
    pie: bool | None = None
    if report.elf_type == "DYN" and report.interpreter is not None:
        pie = True
    elif report.elf_type == "EXEC":
        pie = False
    stack = next((s for s in report.segments if s.type == PT_GNU_STACK), None)
    nx: bool | None = None if stack is None else not (stack.flags & PF_X)
    relro: str | None = None
    if any(s.type == PT_GNU_RELRO for s in report.segments):
        bind_now = any(
            (t == DT_FLAGS and v & DF_BIND_NOW) or (t == DT_FLAGS_1 and v & DF_1_NOW)
            for t, v in dyn_entries
        )
        relro = "full" if bind_now else "partial"
    elif report.segments:
        relro = "none"
    # Absence of a canary symbol only counts as evidence when the dynamic symbol table
    # was actually read; otherwise the answer is unknown, not "no canary".
    has_symbols = bool(report.imported_symbols or report.exported_symbols)
    canary: bool | None = (STACK_CHK_SYMBOL in report.imported_symbols) if has_symbols else None
    return Mitigations(pie=pie, nx=nx, relro=relro, stack_canary=canary)

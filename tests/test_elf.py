from pathlib import Path

import pytest
from elf_builder import build_elf64

from malvax.elf import ElfParseError, analyze_elf, parse_elf_bytes


def test_header_fields_parsed() -> None:
    report = parse_elf_bytes(build_elf64())
    assert report.elf_class == "ELF64"
    assert report.endianness == "little"
    assert report.elf_type == "DYN"
    assert report.machine == "x86-64"
    assert report.entry_point == 0x1000


def test_interpreter_and_needed_libraries() -> None:
    report = parse_elf_bytes(
        build_elf64(interp="/lib64/ld-linux-x86-64.so.2", needed=["libc.so.6", "libm.so.6"])
    )
    assert report.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert report.needed_libraries == ["libc.so.6", "libm.so.6"]


def test_imported_symbols_and_canary_detected() -> None:
    report = parse_elf_bytes(build_elf64(imports=["printf", "__stack_chk_fail"]))
    assert report.imported_symbols == ["printf", "__stack_chk_fail"]
    assert report.mitigations.stack_canary is True


def test_section_names_resolved() -> None:
    names = [s.name for s in parse_elf_bytes(build_elf64()).sections]
    assert ".dynsym" in names and ".dynstr" in names and ".dynamic" in names


def test_pie_and_nx_detected() -> None:
    m = parse_elf_bytes(build_elf64(e_type=3, interp="/ld.so", nx_stack=True)).mitigations
    assert m.pie is True
    assert m.nx is True


def test_non_pie_exec_and_executable_stack() -> None:
    m = parse_elf_bytes(build_elf64(e_type=2, interp="/ld.so", nx_stack=False)).mitigations
    assert m.pie is False
    assert m.nx is False


def test_shared_object_pie_is_undetermined() -> None:
    m = parse_elf_bytes(build_elf64(e_type=3, interp=None)).mitigations
    assert m.pie is None  # a library is not judged on PIE


def test_relro_levels() -> None:
    assert parse_elf_bytes(build_elf64(relro=True, bind_now=True)).mitigations.relro == "full"
    assert parse_elf_bytes(build_elf64(relro=True, bind_now=False)).mitigations.relro == "partial"
    assert parse_elf_bytes(build_elf64(relro=False)).mitigations.relro == "none"


def test_missing_symbols_do_not_claim_missing_canary() -> None:
    # No imports and no exports: the table is empty, so the canary answer is unknown.
    report = parse_elf_bytes(build_elf64(imports=[]))
    assert report.mitigations.stack_canary is None


def test_canary_absent_when_symbols_present() -> None:
    report = parse_elf_bytes(build_elf64(imports=["printf"]))
    assert report.mitigations.stack_canary is False


@pytest.mark.parametrize(
    "data",
    [b"", b"MZ\x90\x00" + b"\x00" * 60, b"\x7fELF\x09" + b"\x00" * 20],
)
def test_rejects_non_elf_and_bad_class(data: bytes) -> None:
    with pytest.raises(ElfParseError):
        parse_elf_bytes(data)


def test_truncated_file_raises_not_crashes() -> None:
    full = build_elf64(imports=["printf"])
    with pytest.raises(ElfParseError):
        parse_elf_bytes(full[:80])


def test_analyze_from_path(tmp_path: Path) -> None:
    f = tmp_path / "fixture.elf"
    f.write_bytes(build_elf64(needed=["libc.so.6"]))
    assert analyze_elf(f).needed_libraries == ["libc.so.6"]

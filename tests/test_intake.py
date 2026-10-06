import hashlib
from pathlib import Path

import pytest

from malvax.intake import (
    SampleRejectedError,
    hash_file,
    identify_file_type,
    intake_sample,
    sanitize_filename,
)


def test_hash_matches_hashlib(tmp_path: Path) -> None:
    data = b"hello malvax" * 1000
    f = tmp_path / "s.bin"
    f.write_bytes(data)
    h = hash_file(f, chunk_size=64)  # small chunks exercise the streaming loop
    assert h.sha256 == hashlib.sha256(data).hexdigest()
    assert h.sha1 == hashlib.sha1(data).hexdigest()  # noqa: S324
    assert h.md5 == hashlib.md5(data).hexdigest()  # noqa: S324


def test_elf_detected_by_magic(tmp_path: Path) -> None:
    f = tmp_path / "x"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert identify_file_type(f) == "ELF"


def test_script_and_unknown(tmp_path: Path) -> None:
    s = tmp_path / "s.sh"
    s.write_bytes(b"#!/bin/sh\necho hi\n")
    u = tmp_path / "u"
    u.write_bytes(b"plain text")
    assert identify_file_type(s) == "SCRIPT"
    assert identify_file_type(u) == "UNKNOWN"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\x\\evil.exe", "evil.exe"),
        ("a b;rm -rf $HOME.elf", "a_b_rm_-rf__HOME.elf"),
        ("   ", "sample.bin"),
        ("", "sample.bin"),
    ],
)
def test_sanitize_filename(raw: str, expected: str) -> None:
    assert sanitize_filename(raw) == expected


def test_intake_rejects_empty_and_oversized(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(SampleRejectedError, match="empty"):
        intake_sample(empty)
    big = tmp_path / "big"
    big.write_bytes(b"A" * 11)
    with pytest.raises(SampleRejectedError, match="limit"):
        intake_sample(big, max_bytes=10)


def test_intake_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(SampleRejectedError, match="not a regular file"):
        intake_sample(tmp_path)


def test_intake_returns_metadata_without_executing(tmp_path: Path) -> None:
    f = tmp_path / "sample"
    f.write_bytes(b"\x7fELF" + b"\x01" * 100)
    meta = intake_sample(f, original_name="../evil name.elf")
    assert meta.filename == "evil_name.elf"
    assert meta.size == 104
    assert meta.file_type == "ELF"
    assert len(meta.hashes.sha256) == 64

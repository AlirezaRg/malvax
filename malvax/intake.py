"""Sample intake: hashing, metadata and file-type identification.

Nothing in this module executes the sample. Files are only opened for reading and
their first bytes are compared against known magic numbers.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_SAMPLE_BYTES = 50 * 1024 * 1024
_CHUNK = 1024 * 1024
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
ELF_MAGIC = b"\x7fELF"


class SampleRejectedError(ValueError):
    """Raised when a sample violates intake rules (size, empty, unreadable)."""


@dataclass(frozen=True, slots=True)
class Hashes:
    sha256: str
    sha1: str
    md5: str


@dataclass(frozen=True, slots=True)
class SampleMetadata:
    filename: str
    size: int
    hashes: Hashes
    file_type: str


def hash_file(path: Path, chunk_size: int = _CHUNK) -> Hashes:
    """Compute SHA-256, SHA-1 and MD5 in a single streaming pass."""
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324 - identifier only
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return Hashes(sha256=sha256.hexdigest(), sha1=sha1.hexdigest(), md5=md5.hexdigest())


def sanitize_filename(name: str) -> str:
    """Reduce a user-supplied name to a safe basename. Never used to build paths or commands."""
    base = os.path.basename(name.replace("\\", "/")).strip()
    cleaned = _SAFE_NAME.sub("_", base)[:200]
    return cleaned or "sample.bin"


def identify_file_type(path: Path) -> str:
    """Identify the file by magic bytes only (no execution, no external tools)."""
    with path.open("rb") as handle:
        head = handle.read(64)
    if head.startswith(ELF_MAGIC):
        return "ELF"
    if head.startswith(b"#!"):
        return "SCRIPT"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP_ARCHIVE"
    return "UNKNOWN"


def intake_sample(
    path: Path,
    original_name: str | None = None,
    max_bytes: int = DEFAULT_MAX_SAMPLE_BYTES,
) -> SampleMetadata:
    """Validate and describe a sample file. Raises SampleRejectedError on rule violations."""
    if not path.is_file():
        raise SampleRejectedError(f"not a regular file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise SampleRejectedError("empty file")
    if size > max_bytes:
        raise SampleRejectedError(f"file is {size} bytes, limit is {max_bytes}")
    return SampleMetadata(
        filename=sanitize_filename(original_name or path.name),
        size=size,
        hashes=hash_file(path),
        file_type=identify_file_type(path),
    )

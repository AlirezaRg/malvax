"""Filesystem monitoring by snapshot diff (Phase 6).

Two snapshots of one watched directory are compared to produce CREATE, MODIFY, DELETE and
RENAME events. Only paths under the watched root are read. Nothing is written or executed.

Limits:
- Snapshot diffing sees the state before and after, not every intermediate step. A file that
  is created and deleted between two snapshots is invisible. Real-time coverage needs inotify
  (Phase 8 or later).
- The process that changed a file is not known from a snapshot. The `process` field stays None
  until an event-based source (fanotify or audit) is added.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

DEFAULT_HASH_LIMIT = 10 * 1024 * 1024  # hash only files up to 10 MiB


class FsOperation(StrEnum):
    CREATE = "CREATE"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    RENAME = "RENAME"


@dataclass(frozen=True, slots=True)
class FileState:
    path: str  # relative to the watched root, POSIX-style
    size: int
    mtime_ns: int
    inode: tuple[int, int]  # (device, inode)
    sha256: str | None


@dataclass(frozen=True, slots=True)
class FsEvent:
    timestamp: str
    operation: FsOperation
    path: str
    old_path: str | None
    size: int | None
    sha256: str | None
    process: str | None = None


def take_snapshot(root: Path, hash_limit: int = DEFAULT_HASH_LIMIT) -> dict[str, FileState]:
    """Record every regular file under root. Symlinks are not followed."""
    root = root.resolve()
    states: dict[str, FileState] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        st = path.stat()
        rel = path.relative_to(root).as_posix()
        digest = _hash_if_small(path, st.st_size, hash_limit)
        states[rel] = FileState(
            path=rel,
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            inode=(st.st_dev, st.st_ino),
            sha256=digest,
        )
    return states


def diff(
    before: dict[str, FileState],
    after: dict[str, FileState],
    timestamp: str | None = None,
) -> list[FsEvent]:
    """Compare two snapshots. Events are sorted by path for reproducible output."""
    now = timestamp or datetime.now(UTC).isoformat()
    events: list[FsEvent] = []
    gone = {p: s for p, s in before.items() if p not in after}
    new = {p: s for p, s in after.items() if p not in before}

    # A file that disappeared at one path and reappeared at another with the same inode is a
    # rename. Inode reuse across unrelated files is possible, so require matching size too.
    by_inode: dict[tuple[int, int], FileState] = {s.inode: s for s in gone.values()}
    renamed_from: set[str] = set()
    for path, state in sorted(new.items()):
        origin = by_inode.get(state.inode)
        if origin is not None and origin.size == state.size and origin.path not in after:
            events.append(
                FsEvent(now, FsOperation.RENAME, path, origin.path, state.size, state.sha256)
            )
            renamed_from.add(origin.path)
        else:
            events.append(
                FsEvent(now, FsOperation.CREATE, path, None, state.size, state.sha256)
            )

    for path, state in sorted(gone.items()):
        if path not in renamed_from:
            events.append(FsEvent(now, FsOperation.DELETE, path, None, state.size, None))

    for path in sorted(set(before) & set(after)):
        old, cur = before[path], after[path]
        if (old.size, old.mtime_ns, old.sha256) != (cur.size, cur.mtime_ns, cur.sha256):
            events.append(FsEvent(now, FsOperation.MODIFY, path, None, cur.size, cur.sha256))

    return events


def _hash_if_small(path: Path, size: int, limit: int) -> str | None:
    if size > limit:
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()

import hashlib
from pathlib import Path

from malvax.fs_monitor import FsOperation, diff, take_snapshot

TS = "2026-01-01T00:00:00+00:00"


def _events(root: Path, action) -> list:
    before = take_snapshot(root)
    action()
    after = take_snapshot(root)
    return diff(before, after, timestamp=TS)


def test_create_reports_path_size_and_hash(tmp_path: Path) -> None:
    events = _events(tmp_path, lambda: (tmp_path / "new.txt").write_bytes(b"abc"))
    assert len(events) == 1
    ev = events[0]
    assert ev.operation is FsOperation.CREATE
    assert ev.path == "new.txt"
    assert ev.size == 3
    assert ev.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert ev.process is None  # snapshot diffing cannot attribute the process


def test_delete(tmp_path: Path) -> None:
    f = tmp_path / "gone.txt"
    f.write_bytes(b"x")
    events = _events(tmp_path, f.unlink)
    assert [(e.operation, e.path) for e in events] == [(FsOperation.DELETE, "gone.txt")]


def test_modify_by_content_change(tmp_path: Path) -> None:
    f = tmp_path / "m.txt"
    f.write_bytes(b"one")
    events = _events(tmp_path, lambda: f.write_bytes(b"two!"))
    assert [e.operation for e in events] == [FsOperation.MODIFY]
    assert events[0].size == 4


def test_rename_is_not_delete_plus_create(tmp_path: Path) -> None:
    f = tmp_path / "old.txt"
    f.write_bytes(b"keep")
    events = _events(tmp_path, lambda: f.rename(tmp_path / "new.txt"))
    assert len(events) == 1
    assert events[0].operation is FsOperation.RENAME
    assert events[0].old_path == "old.txt"
    assert events[0].path == "new.txt"


def test_nested_create_uses_relative_posix_path(tmp_path: Path) -> None:
    def make() -> None:
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "a" / "b" / "c.bin").write_bytes(b"z")

    events = _events(tmp_path, make)
    assert [e.path for e in events] == ["a/b/c.bin"]


def test_large_file_is_not_hashed(tmp_path: Path) -> None:
    (tmp_path / "big.bin").write_bytes(b"A" * 100)
    snap = take_snapshot(tmp_path, hash_limit=10)
    assert snap["big.bin"].sha256 is None
    assert snap["big.bin"].size == 100


def test_no_change_no_events(tmp_path: Path) -> None:
    (tmp_path / "same.txt").write_bytes(b"s")
    assert _events(tmp_path, lambda: None) == []


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_bytes(b"secret")
    root = tmp_path / "watched"
    root.mkdir()
    try:
        (root / "link").symlink_to(target)
    except (OSError, NotImplementedError):
        return  # symlink creation needs privileges on some Windows setups
    assert "link" not in take_snapshot(root)

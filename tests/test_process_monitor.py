import os
import sys
from pathlib import Path

import pytest

from malvax.process_monitor import (
    ProcessRecord,
    build_tree,
    read_process,
    render_tree,
    snapshot,
)


def _make_proc(root: Path, pid: int, ppid: int, comm: str, cmdline: bytes,
               uid: int = 1000, gid: int = 1000) -> None:
    d = root / str(pid)
    d.mkdir(parents=True)
    # 52 fields after the command name; field 4 (index 1) is ppid, field 22 (index 19) starttime.
    rest = ["S", str(ppid)] + ["0"] * 17 + ["123456"] + ["0"] * 30
    (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(rest) + "\n")
    (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                              f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n")
    (d / "cmdline").write_bytes(cmdline)


def test_parses_fake_process(tmp_path: Path) -> None:
    _make_proc(tmp_path, 100, 1, "sample", b"/tmp/sample\x00--flag\x00")
    record = read_process(tmp_path / "100")
    assert record is not None
    assert record.name == "sample"
    assert record.ppid == 1
    assert record.uid == 1000 and record.gid == 1000
    assert record.start_ticks == 123456
    assert record.cmdline == "/tmp/sample --flag"


def test_command_name_with_parentheses_and_spaces(tmp_path: Path) -> None:
    _make_proc(tmp_path, 7, 1, "weird (name) x", b"")
    record = read_process(tmp_path / "7")
    assert record is not None
    assert record.name == "weird (name) x"
    assert record.cmdline == "[weird (name) x]"  # empty cmdline falls back to the name


def test_vanished_process_returns_none(tmp_path: Path) -> None:
    (tmp_path / "55").mkdir()  # no stat/status files: process disappeared mid-read
    assert read_process(tmp_path / "55") is None


def test_snapshot_ignores_non_pid_entries(tmp_path: Path) -> None:
    _make_proc(tmp_path, 10, 1, "a", b"a\x00")
    (tmp_path / "self").mkdir()
    (tmp_path / "meminfo").write_text("x")
    assert [r.pid for r in snapshot(tmp_path)] == [10]


def test_tree_links_child_and_grandchild() -> None:
    records = [
        ProcessRecord(1, 0, "init", "init", 0, 0, 1),
        ProcessRecord(10, 1, "sample", "sample", 1000, 1000, 2),
        ProcessRecord(11, 10, "shell", "sh -c x", 1000, 1000, 3),
        ProcessRecord(12, 11, "child", "child", 1000, 1000, 4),
    ]
    roots = build_tree(records)
    assert [n.record.pid for n in roots] == [1]
    sample = roots[0].children[0]
    assert sample.record.pid == 10
    assert sample.children[0].children[0].record.name == "child"


def test_orphan_becomes_root() -> None:
    records = [ProcessRecord(20, 999, "orphan", "o", 0, 0, 1)]
    assert [n.record.pid for n in build_tree(records)] == [20]


def test_render_tree_shows_branches() -> None:
    records = [
        ProcessRecord(10, 1, "sample", "s", 0, 0, 1),
        ProcessRecord(11, 10, "a", "a", 0, 0, 2),
        ProcessRecord(12, 10, "b", "b", 0, 0, 3),
    ]
    text = render_tree(build_tree(records))
    assert text.splitlines() == [
        "sample (pid 10)",
        "├── a (pid 11)",
        "└── b (pid 12)",
    ]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a real /proc")
def test_live_snapshot_contains_this_process() -> None:
    records = snapshot(Path("/proc"))
    assert os.getpid() in {r.pid for r in records}

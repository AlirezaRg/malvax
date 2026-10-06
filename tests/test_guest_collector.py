"""Tests for the guest telemetry collector. The Linux-only ones use the real /proc and a harmless
child process started by the test itself. Nothing here runs a laboratory sample."""

import sys
from pathlib import Path

import pytest

from malvax.guest_collector import _ancestors_of, collect

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs /proc")


def test_ancestor_chain_follows_parents() -> None:
    parents = {30: 20, 20: 10, 10: 1}
    # Only pids that were observed are in the map, so the chain stops at the last known parent.
    assert _ancestors_of(30, parents) == {30, 20, 10}
    assert _ancestors_of(99, parents) == set()


def test_ancestor_chain_terminates_on_cycle() -> None:
    assert _ancestors_of(5, {5: 6, 6: 5}) == {5, 6}


@linux_only
def test_collect_sees_file_change_and_child_process(tmp_path: Path) -> None:
    watch = tmp_path / "watch"
    watch.mkdir()
    script = (
        "import subprocess, time, pathlib;"
        f"pathlib.Path({str(watch)!r}, 'created.txt').write_text('x');"
        "subprocess.Popen(['sleep', '2']);"
        "time.sleep(2)"
    )
    telemetry = collect([sys.executable, "-c", script], watch, timeout_s=20, sha256="ab" * 32)
    meta = telemetry["execution_metadata"]
    assert meta["exit_code"] == 0 and meta["timeout"] is False
    ops = [(e["operation"], e["path"]) for e in telemetry["filesystem_events"]]
    assert ("CREATE", "created.txt") in ops
    children = [p for p in telemetry["process_events"] if p["name"] == "sleep"]
    assert children, "the sleep child was not observed"
    assert children[0]["ppid"] != 0


@linux_only
def test_collect_kills_and_flags_timeout(tmp_path: Path) -> None:
    watch = tmp_path / "w"
    watch.mkdir()
    telemetry = collect([sys.executable, "-c", "import time; time.sleep(60)"], watch,
                        timeout_s=1, sha256="cd" * 32)
    meta = telemetry["execution_metadata"]
    assert meta["timeout"] is True
    assert meta["exit_code"] != 0
    assert telemetry["syscall_events"] == "NOT_COLLECTED"


@linux_only
def test_sample_output_is_kept_in_telemetry(tmp_path: Path) -> None:
    watch = tmp_path / "o"
    watch.mkdir()
    telemetry = collect([sys.executable, "-c", "print('hello from child')"], watch,
                        timeout_s=10, sha256="ef" * 32)
    assert "hello from child" in telemetry["execution_metadata"]["stdout_text"]
